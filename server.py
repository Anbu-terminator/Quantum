# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re, struct
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

# --- Locate frontend folder robustly ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------- Utility Helpers ----------
def extract_numeric_from_bytes(pt: bytes) -> str:
    """
    Try to interpret decrypted bytes as numeric data.
    Attempts ASCII, then binary-int and float conversions.
    """
    # 1️⃣ Try to decode as ASCII digits
    txt = ''.join(chr(b) for b in pt if 32 <= b <= 126)
    num_match = re.search(r'[-+]?\d*\.?\d+', txt)
    if num_match:
        return num_match.group(0)

    # 2️⃣ Try to unpack bytes as little-endian float or int
    try:
        if len(pt) >= 4:
            val_f = struct.unpack('<f', pt[:4])[0]
            if -1000 < val_f < 10000:
                return f"{val_f:.2f}"
    except Exception:
        pass

    try:
        if len(pt) >= 2:
            val_i = struct.unpack('<H', pt[:2])[0]
            if 0 <= val_i < 10000:
                return str(val_i)
    except Exception:
        pass

    # 3️⃣ Fallback to printable hex
    return re.sub(r'[^0-9A-Za-z.\-]', '', txt) or "N/A"


# --- AES decrypt and clean parse ---
def aes_decrypt_and_clean(cipher_hex: str, key_hex: str, label: str):
    out = {"ok": False, "value": "N/A", "quantum": None, "error": None}
    try:
        if ":" not in cipher_hex:
            out["error"] = "invalid_format"
            return out

        iv_hex, ct_hex = cipher_hex.split(":", 1)
        key = unhexlify(key_hex)
        iv = unhexlify(iv_hex)
        ct = unhexlify(ct_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)

        # Try PKCS7 unpad
        pad_len = pt[-1]
        if 1 <= pad_len <= AES.block_size and pt[-pad_len:] == bytes([pad_len]) * pad_len:
            pt = pt[:-pad_len]

        # Extract Quantum Key if any (ASCII hex pattern)
        try:
            decoded_text = pt.decode("latin-1", errors="ignore")
        except Exception:
            decoded_text = ""
        m_q = re.search(r'([0-9a-fA-F]{32})', decoded_text)
        quantum = m_q.group(1) if m_q else None
        out["quantum"] = quantum

        # Remove quantum bytes from plaintext if found
        if quantum:
            q_bytes = quantum.encode("latin-1", errors="ignore")
            val_bytes = pt.replace(q_bytes, b"")
        else:
            val_bytes = pt

        # For Quantum Key field: directly output the hex
        if label.lower() == "quantum key":
            val_clean = quantum or "N/A"
        else:
            val_clean = extract_numeric_from_bytes(val_bytes)

        out["value"] = val_clean
        out["ok"] = True
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
        if not parsed["ok"]:
            decrypted[label] = f"error:{parsed['error']}"
            continue

        decrypted[label] = parsed["value"]

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })


# --- Serve frontend files ---
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
