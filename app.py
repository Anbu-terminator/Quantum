# server/app.py
import os, base64, json
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from config import *
from quantum_key import start_rotator, get_current_key, get_key_by_id

# start rotator on import
start_rotator(interval=KEY_ROTATE_SECONDS, keep=KEEP_KEYS)

app = Flask(__name__, static_folder="frontend", static_url_path="/")
CORS(app)

# Mongo
mongo = MongoClient(MONGODB_URI)
db = mongo["quantum_iot"]
cipher_collection = db["ciphertexts"]   # stores only ciphertexts

# Serve frontend files (index.html, style.css, script.js)
@app.route("/")
def index():
    return send_from_directory("frontend", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("frontend", path)

# Endpoint: give current quantum key (hex) — requires auth token query param ?auth=...
@app.route("/api/quantum_key", methods=["GET"])
def api_quantum_key():
    token = request.args.get("auth", "")
    if token != ESP_AUTH_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    res = get_current_key()
    if not res:
        return jsonify({"error":"no_key_yet"}), 503
    kid, key_bytes, iv_bytes = res
    return jsonify({
        "key_id": kid,
        "key": key_bytes.hex(),
        "iv": iv_bytes.hex()
    })

# Endpoint: ESP uploads ciphertext JSON: { token, key_id, iv (hex), cipher_b64, post_to_thingspeak (bool) }
# Server stores ciphertext only (no decryption) and returns success.
@app.route("/api/upload", methods=["POST"])
def api_upload():
    data = request.get_json()
    if not data:
        return jsonify({"error":"no_json"}), 400
    token = data.get("token","")
    if token != ESP_AUTH_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    key_id = data.get("key_id","")
    iv_hex = data.get("iv","")
    cipher_b64 = data.get("cipher_b64","")
    post_ts = data.get("post_to_thingspeak", False)

    if not cipher_b64 or not key_id:
        return jsonify({"error":"missing"}), 400

    doc = {
        "key_id": key_id,
        "iv": iv_hex,
        "cipher_b64": cipher_b64,
        "ts": __import__("time").time()
    }
    cipher_collection.insert_one(doc)

    # Optionally post to ThingSpeak (store base64 in field1, key_id to field2)
    if post_ts:
        try:
            import requests
            ts_url = "https://api.thingspeak.com/update"
            payload = {"api_key": THINGSPEAK_WRITE_KEY, "field1": cipher_b64, "field2": key_id}
            r = requests.post(ts_url, data=payload, timeout=10)
            doc["thingspeak_response"] = {"status_code": r.status_code, "text": r.text[:200]}
        except Exception as e:
            doc["thingspeak_error"] = str(e)
            # continue

    return jsonify({"status":"ok"})

# Frontend: get latest ciphertexts (last N)
@app.route("/api/latest", methods=["GET"])
def api_latest():
    limit = int(request.args.get("limit", "10"))
    docs = list(cipher_collection.find({}, {"_id":0}).sort("ts",-1).limit(limit))
    return jsonify(docs)

# (Optional) Admin endpoint to get key info if you want server to decrypt (not used)
@app.route("/api/decrypt_sample", methods=["POST"])
def api_decrypt_sample():
    # not used in secure mode — kept for debug (requires ESP_AUTH_TOKEN)
    data = request.get_json()
    token = data.get("token","")
    if token != ESP_AUTH_TOKEN:
        return jsonify({"error":"unauthorized"}), 401
    key_id = data.get("key_id")
    cipher_b64 = data.get("cipher_b64")
    if not key_id or not cipher_b64:
        return jsonify({"error":"missing"}),400
    keyinfo = get_key_by_id(key_id)
    if not keyinfo:
        return jsonify({"error":"no_such_key"}),404
    key = keyinfo["key"]
    iv = bytes.fromhex(data.get("iv", keyinfo["iv"].hex()))
    ct = base64.b64decode(cipher_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        plain = unpad(cipher.decrypt(ct), AES.block_size).decode("utf-8")
    except Exception as e:
        return jsonify({"error":"decrypt_failed","detail":str(e)}), 500
    return jsonify({"plaintext": plain})

if __name__ == "__main__":
    # Run on 0.0.0.0:5000 — when deploying to Render, Render will use its own port.
    app.run(host="0.0.0.0", port=5000, debug=True)
