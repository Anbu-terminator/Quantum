# server.py
import os
import time
import json
import threading
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import quantum_key
import config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

# start quantum key rotator (uses config.KEY_ROTATE_SECONDS & KEEP_KEYS)
quantum_key.start_rotator()

# ThingSpeak URL (server keeps the read key private)
THINGSPEAK_FEEDS_URL = f"http://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?api_key={config.THINGSPEAK_READ_KEY}&results=20"

@app.route("/api/latest", methods=["GET"])
def api_latest():
    """
    Proxy the latest ThingSpeak feeds (limit 20) and attach qkey_hex info:
      - if an entry has a key_id (field2) and that key_id still exists in quantum_key store, include its hex
      - if not available, attach the current active quantum key hex (so frontend still has a key to try)
    Returns an array of objects with:
      { entry_id, created_at, field1, field2, field3, field4, field5, qkey_hex, qkey_used_id }
    """
    try:
        r = requests.get(THINGSPEAK_FEEDS_URL, timeout=10)
        if r.status_code != 200:
            return jsonify({"error": "thingspeak_fetch_failed", "status": r.status_code}), 502
        data = r.json()
        feeds = data.get("feeds", []) or []
        out = []
        # get current key once (fallback)
        cur = quantum_key.get_current_key()
        cur_kid = None
        cur_key_hex = None
        if cur:
            cur_kid, cur_key_bytes, _ = cur
            cur_key_hex = cur_key_bytes.hex()

        for f in feeds:
            entry_id = f.get("entry_id")
            # read fields straight from ThingSpeak feed
            field1 = f.get("field1")  # ciphertext (base64)
            field2 = (f.get("field2") or "").strip()  # key_id
            field3 = (f.get("field3") or "").strip()  # iv_hex
            field4 = (f.get("field4") or "").strip()  # token
            field5 = (f.get("field5") or "").strip()  # nonce_hex

            qkey_hex = None
            qkey_used_id = None
            if field2:
                ki = quantum_key.get_key_by_id(field2)
                if ki:
                    qkey_hex = ki["key"].hex()
                    qkey_used_id = field2
                else:
                    # requested key_id not found (rotated), fall back to current key
                    qkey_hex = cur_key_hex
                    qkey_used_id = cur_kid
            else:
                # no key_id provided in the feed — use current key
                qkey_hex = cur_key_hex
                qkey_used_id = cur_kid

            out.append({
                "entry_id": entry_id,
                "created_at": f.get("created_at"),
                "field1": field1,
                "field2": field2,
                "field3": field3,
                "field4": field4,
                "field5": field5,
                "qkey_hex": qkey_hex,
                "qkey_used_id": qkey_used_id
            })
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": "exception", "msg": str(e)}), 500

@app.route("/api/quantum_key", methods=["GET"])
def api_quantum_key():
    """
    Return current quantum key or a key by id.
    Keep this endpoint for ESP devices that fetch keys.
    """
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
    file_path = os.path.join(FRONTEND_DIR, path)
    if os.path.exists(file_path):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Starting server on 0.0.0.0:{port}, frontend dir={FRONTEND_DIR}")
    app.run(host="0.0.0.0", port=port, debug=True)
