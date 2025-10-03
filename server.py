# server/server.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
import requests, json, time, base64, threading, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import config
import quantum_key

app = Flask(__name__, static_folder="../frontend", static_url_path="/")
CORS(app)

# MongoDB connection
mongo = MongoClient(config.MONGODB_URI)
db = mongo["q_sense_db"]
stored_col = db["stored_ciphertexts"]   # stores server encrypted blob (no plaintext)
processed_col = db["processed_entries"] # track processed ThingSpeak entry_id

# start quantum key rotator
quantum_key.start_rotator()

# helper: AES bytes from config.SERVER_AES_KEY_HEX
SERVER_AES_KEY = bytes.fromhex(config.SERVER_AES_KEY_HEX)

THINGSPEAK_FEEDS_URL = f"http://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?api_key={config.THINGSPEAK_READ_KEY}&results=20"

POLL_INTERVAL = 15  # seconds

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
                    # skip already processed
                    if processed_col.find_one({"entry_id": entry_id}):
                        continue

                    # read fields
                    cipher_b64 = feed.get("field1") or ""
                    key_id = feed.get("field2") or ""
                    iv_hex  = feed.get("field3") or ""
                    token   = (feed.get("field4") or "").strip()

                    # verify token
                    if token != config.ESP_AUTH_TOKEN:
                        print("[poll] token mismatch for entry", entry_id)
                        # mark processed to avoid repeat attempts (or skip?)
                        processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "bad_token"})
                        continue

                    if not cipher_b64 or not iv_hex:
                        print("[poll] missing cipher or iv for entry", entry_id)
                        processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "missing_fields"})
                        continue

                    # get quantum key by key_id (if present), else use latest
                    qinfo = None
                    if key_id:
                        qinfo = quantum_key.get_key_by_id(key_id)
                    if not qinfo:
                        cur = quantum_key.get_current_key()
                        if cur:
                            key_id, qbytes, qiv = cur
                            qinfo = {"key": qbytes, "iv": qiv}
                        else:
                            print("[poll] no quantum key available")
                            processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "no_key"})
                            continue

                    qkey = qinfo["key"]
                    try:
                        ct = base64.b64decode(cipher_b64)
                        iv = bytes.fromhex(iv_hex)
                        cipher = AES.new(qkey, AES.MODE_CBC, iv)
                        pt = unpad(cipher.decrypt(ct), AES.block_size)
                        # pt is plaintext JSON bytes - convert to string (but we do NOT store plaintext)
                        # Re-encrypt with SERVER_AES_KEY: we will encrypt a JSON object that contains the original quantum fields
                        original_payload = {
                            "cipher_b64": cipher_b64,
                            "key_id": key_id,
                            "iv": iv_hex,
                            "thingspeak_entry_id": entry_id,
                            "received_at": feed.get("created_at")
                        }
                        original_json = json.dumps(original_payload).encode("utf-8")
                        server_iv = os.urandom(16)
                        scipher = AES.new(SERVER_AES_KEY, AES.MODE_CBC, server_iv)
                        scipher_padded = pad(original_json, AES.block_size)
                        sct = scipher.encrypt(scipher_padded)
                        sct_b64 = base64.b64encode(sct).decode()

                        doc = {
                            "entry_id": entry_id,
                            "server_cipher_b64": sct_b64,
                            "server_iv_hex": server_iv.hex(),
                            "stored_at": time.time()
                        }
                        stored_col.insert_one(doc)
                        processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "ok"})
                        print("[poll] processed entry", entry_id)
                    except Exception as e:
                        print("[poll] decryption error for entry", entry_id, e)
                        processed_col.insert_one({"entry_id": entry_id, "ts": time.time(), "note": "decrypt_error", "err": str(e)})

            else:
                print("[poll] thingspeak fetch status", r.status_code)
        except Exception as ex:
            print("[poll] exception:", ex)
        time.sleep(POLL_INTERVAL)

# start poller thread
t = threading.Thread(target=poll_thingspeak_loop, daemon=True)
t.start()

# ----- API endpoints -----

@app.route("/api/quantum_key", methods=["GET"])
def api_quantum_key():
    auth = request.args.get("auth", "")
    key_id = request.args.get("key_id", "")
    if auth != config.ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    if key_id:
        ki = quantum_key.get_key_by_id(key_id)
        if not ki:
            return jsonify({"error":"no_such_key"}), 404
        return jsonify({"key_id": key_id, "key": ki["key"].hex(), "iv": ki["iv"].hex()})
    cur = quantum_key.get_current_key()
    if not cur:
        return jsonify({"error": "no_key_yet"}), 503
    kid, key_bytes, iv_bytes = cur
    return jsonify({"key_id": kid, "key": key_bytes.hex(), "iv": iv_bytes.hex()})

@app.route("/api/latest", methods=["GET"])
def api_latest():
    limit = int(request.args.get("limit", "20"))
    docs = list(stored_col.find({}, {"_id": 0}).sort("stored_at", -1).limit(limit))
    return jsonify(docs)

@app.route("/api/server_key", methods=["GET"])
def api_server_key():
    auth = request.args.get("auth", "")
    if auth != config.ESP_AUTH_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    return jsonify({"server_key": config.SERVER_AES_KEY_HEX})

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("../frontend", path)

if __name__ == "__main__":
    # run HTTP (insecure) server as requested
    app.run(host="0.0.0.0", port=5000, debug=True)
