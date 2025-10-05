# server/server.py
import os, base64, traceback
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from Crypto.Cipher import AES
import quantum_key, config
import requests

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

quantum_key.start_rotator()

def aes_decrypt(ciphertext_b64, key_bytes, iv_bytes):
    try:
        ct = base64.b64decode(ciphertext_b64)
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        pt = cipher.decrypt(ct)
        # PKCS#7 padding
        pad_len = pt[-1]
        if pad_len < 1 or pad_len > 16:
            return None
        return pt[:-pad_len].decode("utf-8", errors="ignore")
    except Exception:
        return None

@app.route("/api/latest")
def api_latest():
    try:
        url = f"http://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?api_key={config.THINGSPEAK_READ_KEY}&results=50"
        r = requests.get(url, timeout=15)
        feeds = r.json().get("feeds", [])

        out = []
        for f in feeds:
            entry_id = f.get("entry_id")
            field1 = f.get("field1")
            field2 = f.get("field2")  # key_id

            ki = quantum_key.get_key_by_id(field2)
            if ki:
                key_bytes = ki["key"]
                iv_bytes = ki["iv"]
                key_used = "exact"
            else:
                cur = quantum_key.get_current_key()
                if cur:
                    _, key_bytes, iv_bytes = cur
                    key_used = "fallback"
                else:
                    key_bytes = iv_bytes = None
                    key_used = None

            decrypted_text = aes_decrypt(field1, key_bytes, iv_bytes) if key_bytes and field1 else None
            decrypt_error = None if decrypted_text else ("decrypt_failed" if field1 else "no_key_available")

            out.append({
                "entry_id": entry_id,
                "field1": field1,
                "field2": field2,
                "key_used": key_used,
                "decrypted_text": decrypted_text,
                "decrypt_error": decrypt_error
            })

        return jsonify(out)
    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Failed to fetch or decrypt feeds"}), 500

@app.route("/api/quantum_key")
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
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=True)
