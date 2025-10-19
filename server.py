# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re
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
def printable_ascii(b: bytes) -> str:
    """Keep only printable ASCII characters."""
    return ''.join(chr(c) for c in b if 32 <= c <= 126).strip()

# --- AES decrypt and clean parse ---
def aes_decrypt_and_clean(cipher_hex: str, key_hex: str):
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
        try:
            pad_len = pt[-1]
            if 1 <= pad_len <= AES.block_size and pt[-pad_len:] == bytes([pad_len]) * pad_len:
                pt = pt[:-pad_len]
        except Exception:
            pass

        # Decode safely (latin-1 keeps all bytes)
        raw_text = pt.decode("latin-1", errors="ignore")

        # --- Extract 32-hex quantum key if present ---
        m_q = re.search(r'([0-9a-fA-F]{32})', raw_text)
        quantum = m_q.group(1) if m_q else None
        out["quantum"] = quantum

        # --- Extract clean numeric/character value before the quantum key ---
        if quantum:
            # Take everything before the quantum hex
            val_part = raw_text.split(quantum)[0]
        else:
            val_part = raw_text

        # Remove non-printable and stray punctuation except digits, '.', '/', and '-'
        val_clean = re.sub(r'[^0-9A-Za-z./\-]', '', val_part).strip()

        # If field is the Quantum Key itself (Arduino sends "Q::challenge::quantum"), handle that
        if val_clean == "" and quantum:
            val_clean = quantum

        out["value"] = val_clean if val_clean else (quantum or "N/A")
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

        parsed = aes_decrypt_and_clean(raw, SERVER_AES_KEY_HEX)
        if not parsed["ok"]:
            decrypted[label] = "N/A"
            continue

        # For the Quantum Key field, show the 32-hex key directly
        if label == "Quantum Key":
            decrypted[label] = parsed["quantum"] or parsed["value"]
        else:
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
