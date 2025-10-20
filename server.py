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

# ---------------- HELPERS ----------------
def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= AES.block_size and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b

def to_clean_ascii(b: bytes) -> str:
    """Convert bytes to readable ASCII, removing non-printables."""
    return ''.join(chr(x) for x in b if 32 <= x <= 126).strip()

def parse_plaintext(pt_bytes: bytes, label: str):
    """
    Extracts sensor value and quantum key from decrypted plaintext.
    Expected structure: <value>::<challenge_id>::<quantum_hex>
    """
    try:
        text = to_clean_ascii(pt_bytes)
        # Look for a valid quantum hex pattern (32–64 hex chars)
        quantum_match = re.search(r'([0-9a-fA-F]{32,64})', text)
        quantum = quantum_match.group(1) if quantum_match else None

        # Split parts
        parts = re.split(r'::', text)
        value = parts[0].strip() if parts else text

        # Remove accidental prefix/suffix junk
        value = re.sub(r'^[^0-9A-Za-z./-]+', '', value)
        value = re.sub(r'[^0-9A-Za-z./-]+$', '', value)

        # Extract numeric or formatted readings
        num_match = re.search(r'[-+]?\d+(?:\.\d+)?(?:/\d+(?:\.\d+)?)?', value)
        if num_match:
            value = num_match.group(0)

        # For Quantum Key: show the actual hex
        if label.lower() == "quantum key":
            value = quantum or "N/A"

        if not value:
            value = "N/A"

        return value, quantum
    except Exception as e:
        logging.warning(f"Parse error {label}: {e}")
        return "N/A", None

def aes_decrypt(cipher_hex: str, key_hex: str, label: str):
    try:
        if ":" not in cipher_hex:
            return "N/A", None
        iv_hex, ct_hex = cipher_hex.split(":", 1)
        iv = unhexlify(iv_hex)
        ct = unhexlify(ct_hex)
        key = unhexlify(key_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = pkcs7_unpad(cipher.decrypt(ct))

        return parse_plaintext(pt, label)
    except Exception as e:
        logging.warning(f"AES decrypt error for {label}: {e}")
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
        "timestamp": latest.get("created_at"),
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
    logging.info(f"✅ Q-SENSE running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
