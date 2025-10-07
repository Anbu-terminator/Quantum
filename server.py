from flask import Flask, jsonify, request, send_from_directory
import os, binascii, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from config import *

# Set Flask static folder to frontend
app = Flask(__name__, static_folder="../frontend", static_url_path="")

# ---------------- Helper functions ----------------
def hx(s):
    return binascii.unhexlify(s)

def aes_decrypt_hex(iv_hex, cipher_hex, key_hex):
    iv = hx(iv_hex)
    ct = hx(cipher_hex)
    key = hx(key_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, AES.block_size)
    except ValueError:
        pass
    return pt.decode('utf-8', errors='replace')

# --------------- Serve frontend -----------------
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    """
    Serve index.html for all routes, so that React-style SPA works.
    """
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        # fallback to index.html
        return send_from_directory(app.static_folder, "index.html")

# --------------- Decrypt ThingSpeak ------------------
@app.route("/decrypt_latest", methods=["GET"])
def decrypt_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json?results=1&api_key={THINGSPEAK_READ_KEY}"
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        return jsonify({"error": "ThingSpeak fetch failed"}), 502
    data = r.json()
    feeds = data.get("feeds", [])
    if not feeds:
        return jsonify({"error":"no feeds"}), 404
    latest = feeds[0]
    out = {}
    for i in range(1,6):
        field_key = f"field{i}"
        raw = latest.get(field_key)
        if raw is None:
            out[field_key] = None
            continue
        raw = raw.strip()
        if ":" in raw:
            iv_hex, cipher_hex = raw.split(":",1)
            try:
                pt = aes_decrypt_hex(iv_hex, cipher_hex, SERVER_AES_KEY_HEX)
                out[field_key] = pt
            except Exception as e:
                out[field_key] = {"error":"decrypt_failed","detail":str(e),"raw":raw}
        else:
            out[field_key] = {"error":"unexpected_format","raw":raw}
    return jsonify({"status":"ok","data":out,"created_at":latest.get("created_at")})

# --------------- Quantum Nonce ------------------
@app.route("/quantum_nonce", methods=["GET"])
def quantum_nonce():
    # You can import and call quantum_key.py function here
    from quantum_key import generate_quantum_nonce
    token = request.args.get("token", "")
    if token != ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    n_bytes = int(request.args.get("n", 16))
    nonce_hex = generate_quantum_nonce(n_bytes)
    return jsonify({"status":"ok","nonce_hex":nonce_hex})

# ------------------- Main ------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
