# backend/server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, base64, json, uuid, os
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from config import *
from quantum_key import get_quantum_challenge

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "../frontend")  # Adjusted for folder structure

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

challenges = {}

# --- AES decrypt helper ---
def aes_decrypt_hex(cipher_hex: str, key_hex: str) -> str:
    """
    Decrypts hex ciphertext of format 'iv:ciphertext' using AES-CBC and hex key.
    """
    try:
        if ":" not in cipher_hex:
            return "invalid_format"

        iv_hex, ct_hex = cipher_hex.split(":")
        key = unhexlify(key_hex)
        iv = unhexlify(iv_hex)
        ct = unhexlify(ct_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode("utf-8", errors="ignore")
    except Exception as e:
        return f"error:{e}"

# --- Fetch latest feed from ThingSpeak ---
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# --- API: Quantum Key Generator (for ESP8266) ---
@app.route("/quantum", methods=["GET"])
def api_quantum():
    token = request.args.get("token")
    if token != ESP_AUTH_TOKEN:
        abort(401)
    n = int(request.args.get("n", 16))
    q_hex = get_quantum_challenge(n)
    return jsonify({"ok": True, "quantum_hex": q_hex})

# --- API: Decrypt latest ThingSpeak feed ---
@app.route("/api/latest", methods=["GET"])
def api_latest():
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)
    try:
        data = fetch_thingspeak_latest()
    except Exception as e:
        return jsonify({"error": f"ThingSpeak fetch failed: {e}"}), 500

    feeds = data.get("feeds", [])
    if not feeds:
        return jsonify({"error": "No feed data"}), 404

    latest = feeds[-1]

    fields = {
        "field1": "Quantum Key",
        "field2": "Temperature",
        "field3": "Humidity",
        "field4": "IR Sensor",
        "field5": "MAX30100",
    }

    decrypted = {}

    for fkey, label in fields.items():
        raw = latest.get(fkey)
        if not raw:
            decrypted[label] = "None"
            continue

        dec = aes_decrypt_hex(raw, SERVER_AES_KEY_HEX)
        decrypted[label] = dec

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })

# --- Serve frontend files ---
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.isfile(full_path):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# --- Main entry (HTTPS) ---
if __name__ == "__main__":
    # Run with HTTPS using an adhoc self-signed certificate
    # Compatible with ESP8266 client.setInsecure()
    app.run(
        host="0.0.0.0",
        port=5000,
        ssl_context="adhoc",  # Enables temporary self-signed SSL certificate
        debug=True
    )
