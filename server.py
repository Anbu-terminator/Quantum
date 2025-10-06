# backend/server.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
import requests, json, time, base64, threading, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import config
import quantum_key

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(os.path.dirname(BASE_DIR), "frontend")  # repo_root/frontend

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

# Mongo
mongo = MongoClient(config.MONGODB_URI) if hasattr(config, "MONGODB_URI") else MongoClient()
db = mongo.get_database("q_sense_db")
stored_col = db["stored_ciphertexts"]
processed_col = db["processed_entries"]

# start quantum key rotator
quantum_key.start_rotator(config.KEY_ROTATE_SECONDS, config.KEEP_KEYS)

SERVER_AES_KEY = bytes.fromhex(config.SERVER_AES_KEY_HEX)

THINGSPEAK_FEEDS_URL = f"http://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?api_key={config.THINGSPEAK_READ_KEY}&results=50"
POLL_INTERVAL = 15

def poll_thingspeak_loop():
    while True:
        try:
            r = requests.get(THINGSPEAK_FEEDS_URL, timeout=10)
            if r.status_code == 200:
                data = r.json()
                feeds = data.get("feeds", [])
                for feed in feeds:
                    entry_id = feed.get("entry_id")
                    if not entry_id:
                        continue
                    if processed_col.find_one({"entry_id": entry_id}):
                        continue

                    # per-field ciphertexts
                    temp_ct_b64 = feed.get("field1") or ""   # Temperature encrypted (base64)
                    hum_ct_b64  = feed.get("field2") or ""   # Humidity encrypted
                    ir_ct_b64   = feed.get("field3") or ""   # IR encrypted
                    key_id      = feed.get("field4") or ""   # key id
                    extra_label = feed.get("field5") or ""   # arbitrary label
                    token       = (feed.get("field6") or "").strip()  # ESP token placed in field6

                    if token != config.ESP_AUTH_TOKEN:
                        print("[poll] bad token for entry", entry_id)
                        processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "bad_token"})
                        continue

                    # require at least one ct and iv embedded? We expect ivs are included inside each ciphertext payload as JSON? 
                    # Our ESP will send simple base64 of AES_CBC ciphertext and will pass iv as part of payload we will include in ciphertext formatting: 
                    # For simplicity: ESP will send base64 string where first 32 hex chars encode IV? (we chose sending iv separately not possible via fields)
                    # Here we assume the ESP **prepended IV hex (32 chars)** + '.' + base64(cipher) in each field.
                    def parse_field(field_str):
                        # expected format "IVHEX.B64"
                        if not field_str:
                            return None,None
                        if '.' in field_str:
                            ivhex, b64 = field_str.split('.',1)
                            return ivhex, b64
                        return None, field_str

                    temp_iv_hex, temp_b64 = parse_field(temp_ct_b64)
                    hum_iv_hex, hum_b64   = parse_field(hum_ct_b64)
                    ir_iv_hex,  ir_b64    = parse_field(ir_ct_b64)

                    # get quantum key
                    qinfo = None
                    if key_id:
                        qinfo = quantum_key.get_key_by_id(str(key_id))
                    if not qinfo:
                        cur = quantum_key.get_current_key()
                        if cur:
                            key_id, qbytes, qiv = cur
                            qinfo = {"key": qbytes, "iv": qiv}
                        else:
                            print("[poll] no quantum key")
                            processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "no_key"})
                            continue

                    qkey = qinfo["key"]
                    try:
                        # attempt to decrypt each field if present
                        def decrypt_field(ivhex, b64):
                            if not b64 or not ivhex:
                                return None
                            ct = base64.b64decode(b64)
                            iv = bytes.fromhex(ivhex)
                            dec = unpad(AES.new(qkey, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)
                            return dec.decode('utf-8')

                        temp_plain = decrypt_field(temp_iv_hex, temp_b64)
                        hum_plain  = decrypt_field(hum_iv_hex, hum_b64)
                        ir_plain   = decrypt_field(ir_iv_hex, ir_b64)

                        # Store original quantum ciphertext metadata (not plaintext)
                        record = {
                            "entry_id": entry_id,
                            "received_at": feed.get("created_at"),
                            "key_id": key_id,
                            "temp_ct": temp_ct_b64,
                            "hum_ct": hum_ct_b64,
                            "ir_ct": ir_ct_b64,
                            "extra_label": extra_label,
                            "stored_at": time.time()
                        }
                        # Re-encrypt record with server AES before storage
                        rec_json = json.dumps(record).encode('utf-8')
                        server_iv = os.urandom(16)
                        scipher = AES.new(SERVER_AES_KEY, AES.MODE_CBC, server_iv)
                        sct = scipher.encrypt(pad(rec_json, AES.block_size))
                        sct_b64 = base64.b64encode(sct).decode()

                        stored_col.insert_one({
                            "entry_id": entry_id,
                            "server_cipher_b64": sct_b64,
                            "server_iv_hex": server_iv.hex(),
                            "stored_at": time.time()
                        })

                        processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "ok"})
                        print("[poll] processed", entry_id, "temp_plain:", temp_plain, "hum_plain:", hum_plain, "ir_plain:", ir_plain)
                    except Exception as e:
                        print("[poll] decrypt error", entry_id, e)
                        processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "decrypt_error", "err": str(e)})
            else:
                print("[poll] thingspeak status", r.status_code)
        except Exception as ex:
            print("[poll] exception", ex)
        time.sleep(POLL_INTERVAL)

# start poller
t = threading.Thread(target=poll_thingspeak_loop, daemon=True)
t.start()

# --- API endpoints ---
@app.route("/api/quantum_key", methods=["GET"])
def api_quantum_key():
    auth = request.args.get("auth", "")
    key_id = request.args.get("key_id", "")
    if auth != config.ESP_AUTH_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    if key_id:
        ki = quantum_key.get_key_by_id(key_id)
        if not ki:
            return jsonify({"error":"no_such_key"}), 404
        return jsonify({"key_id": key_id, "key": ki["key"].hex(), "iv": ki["iv"].hex()})
    cur = quantum_key.get_current_key()
    if not cur:
        return jsonify({"error":"no_key_yet"}), 503
    kid, key_bytes, iv_bytes = cur
    return jsonify({"key_id": kid, "key": key_bytes.hex(), "iv": iv_bytes.hex()})

@app.route("/api/latest", methods=["GET"])
def api_latest():
    limit = int(request.args.get("limit", "20"))
    docs = list(stored_col.find({}, {"_id":0}).sort("stored_at", -1).limit(limit))
    return jsonify(docs)

@app.route("/api/server_key", methods=["GET"])
def api_server_key():
    auth = request.args.get("auth", "")
    if auth != config.ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"server_key": config.SERVER_AES_KEY_HEX})

# Serve frontend files
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def static_files(path):
    file_path = os.path.join(FRONTEND_DIR, path)
    if os.path.exists(file_path):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")

# run
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
