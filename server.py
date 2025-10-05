# server.py
import os, json, base64
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
from Crypto.Cipher import AES
import quantum_key
import config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

# Start rotator using config values
quantum_key.start_rotator()

THINGSPEAK_FEEDS_URL = (
    f"http://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json"
    f"?api_key={config.THINGSPEAK_READ_KEY}&results=20"
)

def decrypt_field(cipher_b64, key_bytes, iv_bytes):
    """Decrypt Base64 AES-CTR ciphertext with given key & IV"""
    if not cipher_b64 or not key_bytes or not iv_bytes:
        return None, "no_data_or_key"
    try:
        cipher_bytes = base64.b64decode(cipher_b64)
        cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=iv_bytes)
        decrypted_bytes = cipher.decrypt(cipher_bytes)
        try:
            decrypted_text = decrypted_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decrypted_text = None
            return None, "malformed_utf8"
        return decrypted_text, None
    except Exception:
        return None, "decrypt_failed"

@app.route("/api/latest", methods=["GET"])
def api_latest():
    try:
        r = requests.get(THINGSPEAK_FEEDS_URL, timeout=12)
        if r.status_code != 200:
            return jsonify({"error": "thingspeak_fetch_failed", "status": r.status_code}), 502

        data = r.json()
        feeds = data.get("feeds", []) or []

        # get current key once for fallback
        cur = quantum_key.get_current_key()
        cur_kid = None
        cur_key_bytes = None
        cur_iv_bytes = None
        if cur:
            cur_kid, cur_key_bytes, cur_iv_bytes = cur

        # get all keys in rotator for trial
        all_keys = quantum_key.get_all_keys()  # returns list of dicts: [{"key_id":..., "key":..., "iv":...}, ...]

        out = []
        for f in feeds:
            entry_id = f.get("entry_id")
            field1 = f.get("field1")  # ciphertext b64
            field2 = (f.get("field2") or "").strip()  # key_id
            field3 = (f.get("field3") or "").strip()
            field4 = (f.get("field4") or "").strip()
            field5 = (f.get("field5") or "").strip()

            qkey_hex = None
            key_used = None
            decrypted_text = None
            decrypt_error = None

            tried_keys = []

            # 1) Try exact key if field2 provided
            if field2:
                ki = quantum_key.get_key_by_id(field2)
                if ki:
                    tried_keys.append((ki["key"], ki["iv"], "exact"))
                else:
                    # if exact key not found, we'll try all keys later
                    pass

            # 2) Add all keys from rotator (avoid duplicates)
            for k in all_keys:
                if field2 and k["key_id"] == field2:
                    continue  # already tried exact key
                tried_keys.append((k["key"], k["iv"], "rotator"))

            # 3) Add current key as fallback if not already tried
            if cur_key_bytes and (not tried_keys or tried_keys[-1][0] != cur_key_bytes):
                tried_keys.append((cur_key_bytes, cur_iv_bytes, "fallback"))

            # Try decryption sequentially
            for k_bytes, iv_bytes, usage in tried_keys:
                decrypted_text, decrypt_error = decrypt_field(field1, k_bytes, iv_bytes)
                if decrypted_text is not None:
                    key_used = usage
                    qkey_hex = k_bytes.hex()
                    decrypt_error = None
                    break

            out.append({
                "entry_id": entry_id,
                "created_at": f.get("created_at"),
                "field1": field1,
                "decrypted_text": decrypted_text,
                "decrypt_error": decrypt_error,
                "field2": field2,
                "field3": field3,
                "field4": field4,
                "field5": field5,
                "key_used": key_used,
                "qkey_hex": qkey_hex
            })

        return jsonify(out)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/quantum_key", methods=["GET"])
def api_quantum_key():
    auth = request.args.get("auth", "")
    key_id = request.args.get("key_id", "")
    if auth != config.ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    if key_id:
        ki = quantum_key.get_key_by_id(key_id)
        if not ki:
            return jsonify({"error": "no_such_key"}), 404
        return jsonify({"key_id": key_id, "key": ki["key"].hex(), "iv": ki["iv"].hex()})
    cur = quantum_key.get_current_key()
    if not cur:
        return jsonify({"error": "no_key_yet"}), 503
    kid, key_bytes, iv_bytes = cur
    return jsonify({"key_id": kid, "key": key_bytes.hex(), "iv": iv_bytes.hex()})

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def static_files(path):
    fp = os.path.join(FRONTEND_DIR, path)
    if os.path.exists(fp):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting server on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
