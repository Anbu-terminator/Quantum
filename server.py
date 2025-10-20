# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

# --- Locate frontend folder ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------- AESLib-Compatible Decryption ----------
def aeslib_decrypt(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ct = unhexlify(ct_hex)

    ecb = AES.new(key, AES.MODE_ECB)
    block_size = 16
    out = b""
    prev = iv

    # Manual CBC decryption
    for i in range(0, len(ct), block_size):
        block = ct[i:i+block_size]
        dec_block = ecb.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(dec_block, prev))
        out += plain_block
        prev = block

    # Remove PKCS#7 padding
    pad_len = out[-1]
    if 1 <= pad_len <= 16:
        out = out[:-pad_len]
    return out

# ---------- AES Decrypt and Clean ----------
def aes_decrypt_and_clean(cipher_hex: str, key_hex: str, label: str):
    out = {"ok": False, "value": "N/A", "quantum": None, "error": None}
    try:
        if ":" not in cipher_hex:
            out["error"] = "invalid_format"
            return out

        iv_hex, ct_hex = cipher_hex.split(":", 1)
        pt_bytes = aeslib_decrypt(iv_hex, ct_hex, key_hex)
        raw_text = pt_bytes.decode("latin-1", errors="ignore").strip()

        # Extract format: <value>::<challenge>::<quantum_hex>
        parts = raw_text.split("::")
        value, quantum = "N/A", None
        if len(parts) >= 3:
            value = parts[0].strip()
            quantum = parts[-1].strip()
        elif len(parts) == 1:
            value = parts[0].strip()

        # Keep printable characters only (preserves dots, colons, slash, numbers)
        value = "".join(c for c in value if c.isprintable())

        # Quantum Key field uses the quantum hex
        if label.lower() == "quantum key":
            value = quantum or value

        out["ok"] = True
        out["value"] = value
        out["quantum"] = quantum

        # Optional debug
        print(f"DEBUG {label}: raw_text='{raw_text}', value='{value}', quantum='{quantum}'")

        return out

    except Exception as e:
        out["error"] = str(e)
        return out

# --- Fetch latest ThingSpeak feed ---
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# --- API: Quantum Key Generator ---
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
            decrypted[label] = "N/A"
            continue

        parsed = aes_decrypt_and_clean(raw, SERVER_AES_KEY_HEX, label)
        decrypted[label] = parsed["value"] if parsed["ok"] else f"error:{parsed['error']}"

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })

# --- Serve frontend ---
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full_path):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# --- Run App ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"✅ Q-SENSE running at http://127.0.0.1:{port}")
    print(f"📁 Serving frontend from: {FRONTEND_FOLDER}")
    app.run(host="0.0.0.0", port=port, debug=True)
