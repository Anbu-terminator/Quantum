# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

# ---------- FRONTEND FOLDER ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------- AES DECRYPT ----------
def aes_decrypt(cipher_hex: str, key_hex: str):
    """Decrypt AES-CBC hex data and return raw plaintext string."""
    try:
        if ":" not in cipher_hex:
            return None
        iv_hex, ct_hex = cipher_hex.split(":", 1)
        iv = unhexlify(iv_hex)
        ct = unhexlify(ct_hex)
        key = unhexlify(key_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)

        # PKCS#7 unpad
        pad_len = pt[-1]
        if 1 <= pad_len <= AES.block_size:
            pt = pt[:-pad_len]

        # decode safely
        text = pt.decode("latin-1", errors="ignore")
        return text.strip()
    except Exception as e:
        return f"error:{e}"

# ---------- PARSE PLAINTEXT ----------
def parse_plaintext(text: str):
    """
    Given plaintext like '25.3::17123456-5678::6b9cb0aacc...',
    return the sensor value (first segment) and quantum key (last segment).
    """
    parts = text.split("::")
    if len(parts) >= 3:
        value = parts[0].strip()
        quantum = parts[-1].strip()
        return value, quantum
    elif len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    else:
        # fallback: extract printable ASCII
        clean = ''.join(ch for ch in text if 32 <= ord(ch) <= 126)
        return clean, None

# ---------- FETCH THINGSPEAK ----------
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# ---------- API: Quantum ----------
@app.route("/quantum", methods=["GET"])
def api_quantum():
    token = request.args.get("token")
    if token != ESP_AUTH_TOKEN:
        abort(401)
    n = int(request.args.get("n", 16))
    q_hex = get_quantum_challenge(n)
    return jsonify({"ok": True, "quantum_hex": q_hex})

# ---------- API: LATEST ----------
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
            decrypted[label] = "N/A"
            continue

        text = aes_decrypt(raw, SERVER_AES_KEY_HEX)
        if text is None or text.startswith("error:"):
            decrypted[label] = "N/A"
            continue

        value, quantum = parse_plaintext(text)

        # Special: for Quantum Key field show the quantum itself
        if label == "Quantum Key":
            decrypted[label] = quantum or value or "N/A"
        else:
            decrypted[label] = value or "N/A"

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at"),
    })

# ---------- SERVE FRONTEND ----------
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full_path):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# ---------- MAIN ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"✅ Q-SENSE running at http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
