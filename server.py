# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re, logging
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

logging.basicConfig(level=logging.INFO)

# ---------------- FRONTEND PATH ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------------- UTILITIES ----------------
def pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding cleanly."""
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= AES.block_size and all(p == pad for p in data[-pad:]):
        return data[:-pad]
    return data

def clean_ascii(data: bytes) -> str:
    """Keep only printable ASCII (32–126)."""
    return ''.join(chr(c) for c in data if 32 <= c <= 126)

def parse_decrypted_text(pt: str, label: str):
    """
    Extract the <value>::<challenge_id>::<quantum_hex> parts.
    """
    # Remove any accidental nulls or line breaks
    pt = pt.strip().replace('\x00', '')

    # Split by :: since that’s how Arduino formats
    parts = pt.split("::")

    value = "N/A"
    quantum = None

    if len(parts) >= 3:
        value = parts[0].strip()
        quantum = re.sub(r'[^0-9a-fA-F]', '', parts[-1])  # last is quantum key
    elif len(parts) == 1:
        # fallback: single value only
        value = re.sub(r'[^0-9A-Za-z./-]', '', parts[0])
    else:
        value = "N/A"

    # Extra cleanups for sensors
    if label.lower() != "quantum key":
        match = re.search(r'[-+]?\d+(?:\.\d+)?(?:/\d+(?:\.\d+)?)?', value)
        if match:
            value = match.group(0)
    else:
        value = quantum or "N/A"

    return value, quantum

def aes_decrypt(cipher_hex: str, key_hex: str, label: str):
    """Decrypt AES CBC from ThingSpeak data."""
    try:
        if ":" not in cipher_hex:
            return "N/A", None

        iv_hex, ct_hex = cipher_hex.split(":", 1)
        iv = unhexlify(iv_hex)
        ct = unhexlify(ct_hex)
        key = unhexlify(key_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt = pkcs7_unpad(pt)
        text = clean_ascii(pt)

        val, quantum = parse_decrypted_text(text, label)
        logging.info(f"[{label}] => {val}")
        return val, quantum
    except Exception as e:
        logging.warning(f"Decrypt error ({label}): {e}")
        return "N/A", None

# ---------------- THINGSPEAK ----------------
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# ---------------- API ROUTES ----------------
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
        val, quantum = aes_decrypt(raw, SERVER_AES_KEY_HEX, label)
        decrypted[label] = val

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })

# ---------------- FRONTEND ----------------
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full_path):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# ---------------- MAIN ----------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logging.info(f"✅ Q-SENSE running at http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
