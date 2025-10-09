# backend/server.py
from flask import Flask, jsonify, request, abort, send_from_directory
import os
import requests
import base64
import hmac
import hashlib
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from config import *

# Frontend folder (relative to backend.py)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.normpath(os.path.join(BASE_DIR, "../frontend"))

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# In-memory store for challenges issued to devices:
# key: challenge_id -> { "token": <challenge_token>, "status": "pending" | "done" | "failed", "meta": {...} }
challenges = {}

# ThingSpeak feeds URL
TS_CHANNEL_FEEDS_URL = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"

# ---------------- AES decrypt helper ----------------
def aes_decrypt_base64(cipher_b64: str) -> str:
    if not cipher_b64:
        return None
    try:
        # base64 decode (standard base64 from ESP output)
        ct = base64.b64decode(cipher_b64)
        key = unhexlify(SERVER_AES_KEY_HEX)
        iv = unhexlify(AES_IV_HEX)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode("utf-8")
    except Exception as e:
        # decryption failed
        print("AES decrypt error:", e)
        return None

# ---------------- HMAC verify helper ----------------
def verify_hmac_b64(hmac_b64: str, message: str, key: str) -> bool:
    """
    Compare provided urlsafe base64(no padding) HMAC against computed HMAC-SHA256(key, message).
    Device uses urlsafe base64 (replace +/ with -_ and trimmed '=').
    """
    if hmac_b64 is None:
        return False
    try:
        # compute HMAC-SHA256
        hm = hmac.new(key.encode('utf-8'), msg=message.encode('utf-8'), digestmod=hashlib.sha256).digest()
        # urlsafe base64 encode without '=' padding
        expected = base64.urlsafe_b64encode(hm).decode('utf-8').rstrip('=')
        return hmac.compare_digest(expected, hmac_b64)
    except Exception as e:
        print("HMAC verify error:", e)
        return False

# ---------------- Quantum challenge endpoint ----------------
@app.route("/quantum/challenge", methods=["GET"])
def quantum_challenge():
    """
    Device calls this to get a fresh challenge token and ID.
    Returned JSON: { ok: True, challenge_id: "...", challenge_token: "..." }
    The token is stored in-memory so backend can verify HMACs later.
    """
    # create random id + token (URL-safe base64)
    challenge_id = base64.urlsafe_b64encode(os.urandom(9)).decode('utf-8').rstrip('=')
    challenge_token = base64.urlsafe_b64encode(os.urandom(24)).decode('utf-8').rstrip('=')
    challenges[challenge_id] = {"token": challenge_token, "status": "pending"}
    return jsonify({"ok": True, "challenge_id": challenge_id, "challenge_token": challenge_token})

@app.route("/quantum/status/<challenge_id>", methods=["GET"])
def quantum_status(challenge_id):
    ch = challenges.get(challenge_id)
    if not ch:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "challenge": ch})

# ---------------- ThingSpeak fetch + decrypt + verify ----------------
@app.route("/feeds/latest", methods=["GET"])
def feeds_latest():
    """
    Fetch the latest feed from ThingSpeak, decrypt each field and verify HMAC (if attached).
    Returns JSON structure listing decrypted values and hmac check results.
    Field format expected from ESP:
      fieldN = "<cipher_b64>::<hmac_b64>:<timestamp>:<challenge_id>"
    """
    # optional token protection (frontend/device may pass ?auth=ESP_AUTH_TOKEN)
    token = request.args.get("auth")
    if token and token != ESP_AUTH_TOKEN:
        return jsonify({"error": "Unauthorized"}), 401

    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    try:
        r = requests.get(TS_CHANNEL_FEEDS_URL, params=params, timeout=10)
        r.raise_for_status()
    except Exception as e:
        return jsonify({"error": "ThingSpeak fetch failed", "detail": str(e)}), 502

    obj = r.json()
    feeds = obj.get("feeds", [])
    if not feeds:
        return jsonify({"error": "no feeds"}), 404

    feed = feeds[-1]  # latest

    # friendly names
    mapping = {
        "field1": "Label1",
        "field2": "Temperature",
        "field3": "Humidity",
        "field4": "IR",
        "field5": "Label2"
    }

    result = {}
    for fkey, fname in mapping.items():
        raw = feed.get(fkey)
        if not raw:
            result[fname] = {"value": None, "hmac_ok": None, "note": "empty"}
            continue

        # split payload
        cipher_b64 = None
        hmac_b64 = None
        ts = None
        challenge_id = None

        if "::" in raw:
            cipher_b64, suffix = raw.split("::", 1)
            # suffix expected "hmac_b64:timestamp:challenge_id"
            parts = suffix.split(":")
            if len(parts) >= 3:
                hmac_b64 = parts[0]
                ts = parts[1]
                challenge_id = parts[2]
            else:
                # fallback: treat entire suffix as hmac (older formats)
                hmac_b64 = parts[0] if parts else None
        else:
            cipher_b64 = raw

        # decrypt ciphertext
        plaintext = aes_decrypt_base64(cipher_b64)

        # verify HMAC if challenge_id present
        hmac_ok = None
        challenge_info = None
        if challenge_id:
            challenge_info = challenges.get(challenge_id)
            if challenge_info:
                challenge_token = challenge_info.get("token")
                # message used by device for HMAC: "<FieldLabel>:<timestamp>:<challenge_token>"
                message = f"{fname}:{ts}:{challenge_token}"
                hmac_ok = verify_hmac_b64(hmac_b64, message, IBM_API_TOKEN)
            else:
                hmac_ok = False

        result[fname] = {
            "value": plaintext,
            "hmac_ok": hmac_ok,
            "hmac": hmac_b64,
            "timestamp": ts,
            "challenge_id": challenge_id,
            "challenge": challenge_info
        }

    # include raw feed for debugging if needed
    return jsonify({"decrypted": result, "_raw_feed": feed})

# ---------------- frontend static serve (SPA friendly) ----------------
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    # Serve files from frontend folder; fallback to index.html for SPA routes
    if path != "" and os.path.exists(os.path.join(FRONTEND_FOLDER, path)):
        return send_from_directory(FRONTEND_FOLDER, path)
    index_path = os.path.join(FRONTEND_FOLDER, "index.html")
    if os.path.exists(index_path):
        return send_from_directory(FRONTEND_FOLDER, "index.html")
    return jsonify({"error": "index.html not found"}), 404

# ---------------- run ----------------
if __name__ == "__main__":
    print("Frontend folder:", FRONTEND_FOLDER)
    app.run(host="0.0.0.0", port=5000, debug=True)
