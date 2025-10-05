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

# Start quantum key rotator (so ESP can still request keys)
quantum_key.start_rotator(interval=getattr(config, "KEY_ROTATE_SECONDS", 60),
                          keep=getattr(config, "KEEP_KEYS", 10))

# ThingSpeak feed URL (server-side uses read key; this hides the read key from browser)
THINGSPEAK_FEEDS_URL = f"http://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?api_key={config.THINGSPEAK_READ_KEY}&results=50"

@app.route("/api/latest", methods=["GET"])
def api_latest():
    """
    Proxy latest feeds from ThingSpeak and return them as JSON.
    We DO NOT decrypt here — the frontend will decrypt using the quantum key + nonce.
    Returned structure: array of feed objects with entry_id, created_at, field1..field5
    """
    try:
        r = requests.get(THINGSPEAK_FEEDS_URL, timeout=10)
        if r.status_code != 200:
            return jsonify({"error": "thingspeak_fetch_failed", "status": r.status_code}), 502
        data = r.json()
        feeds = data.get("feeds", [])
        # Only return the useful fields; keep entire feed object if you want
        out = []
        for f in feeds:
            out.append({
                "entry_id": f.get("entry_id"),
                "created_at": f.get("created_at"),
                "field1": f.get("field1"),  # cipher_b64
                "field2": f.get("field2"),  # key_id
                "field3": f.get("field3"),  # iv_hex
                "field4": f.get("field4"),  # token
                "field5": f.get("field5")   # nonce_hex
            })
        return jsonify(out)
    except Exception as e:
        return jsonify({"error": "exception", "msg": str(e)}), 500

@app.route("/api/quantum_key", methods=["GET"])
def api_quantum_key():
    """
    Returns current quantum key or key by id.
    Requires auth == ESP_AUTH_TOKEN (same as before).
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

@app.route("/api/server_key", methods=["GET"])
def api_server_key():
    """
    If you still need server AES key endpoint (used previously), we return it if auth matches.
    Frontend does not strictly need it in this new design (we decrypt directly from ThingSpeak).
    """
    auth = request.args.get("auth", "")
    if auth != config.ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"server_key": getattr(config, "SERVER_AES_KEY_HEX", "")})

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
    print("Starting server on 0.0.0.0:%d" % port)
    app.run(host="0.0.0.0", port=port, debug=True)
