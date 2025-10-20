# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re, logging
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

logging.basicConfig(level=logging.INFO)

# Locate frontend folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------- Helpers ----------
def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= AES.block_size and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b

def clean_text(s: str) -> str:
    s = s.strip().replace('\x00', '')
    s = re.sub(r'[^0-9A-Za-z./:+-]', '', s)
    return s

def parse_value_from_plaintext(pt_bytes: bytes, label: str):
    """Extract value from plaintext like '25.5::id::quantum'."""
    try:
        txt = pt_bytes.decode('latin-1', errors='ignore')
        txt = txt.strip()
        # Split on "::"
        if "::" in txt:
            parts = txt.split("::")
            value = parts[0]
        else:
            value = txt

        value = clean_text(value)

        # Extract 32-char quantum hex
        qmatch = re.search(r'([0-9a-fA-F]{32})', txt)
        quantum = qmatch.group(1) if qmatch else None

        # If Quantum Key field, show the hex instead of 'Q'
        if label.lower() == "quantum key":
            return quantum or value or "N/A", quantum

        # Normalize numeric-like outputs
        val_match = re.search(r'[-+]?\d+(?:\.\d+)?(?:/\d+(?:\.\d+)?)?', value)
        if val_match:
            return val_match.group(0), quantum

        return value or "N/A", quantum
    except Exception:
        return "N/A", None

def aes_decrypt(cipher_hex: str, key_hex: str, label: str):
    try:
        # Parse iv:ciphertext
        if ":" not in cipher_hex:
            return "N/A", None
        iv_hex, ct_hex = cipher_hex.split(":", 1)
        iv = unhexlify(iv_hex.strip())
        ct = unhexlify(ct_hex.strip())
        key = unhexlify(key_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = pkcs7_unpad(cipher.decrypt(ct))

        value, quantum = parse_value_from_plaintext(pt, label)
        return value, quantum
    except Exception as e:
        logging.warning(f"Decrypt error for {label}: {e}")
        return "N/A", None

# ---------- ThingSpeak ----------
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# ---------- API ----------
@app.route("/quantum", methods=["GET"])
def api_quantum():
    token = request.args.get("token")
    if token != ESP_AUTH_TOKEN:
        abort(401)
    n = int(request.args.get("n", 16))
    q_hex = get_quantum_challenge(n)
    return jsonify({"ok": True, "quantum_hex": q_hex})

@app.route("/api/latest", methods=["GET"])
def api_latest():
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)
    try:
        data = fetch_thingspeak_latest()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    feeds = data.get("feeds", [])
    if not feeds:
        return jsonify({"error": "No feed data"}), 404
    latest = feeds[-1]

    fields = {
        "field1": "Quantum Key",
        "field2": "Temperature",
        "field3": "Humidity",
        "field4": "IR Sensor",
        "field5": "MAX30100"
    }

    decrypted = {}
    for fkey, label in fields.items():
        raw = latest.get(fkey)
        if not raw:
            decrypted[label] = "N/A"
            continue
        val, quantum = aes_decrypt(raw, SERVER_AES_KEY_HEX, label)
        decrypted[label] = val

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })

# ---------- Frontend ----------
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full_path):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logging.info(f"✅ Q-SENSE running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
