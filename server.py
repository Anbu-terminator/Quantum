# server.py — Q-SENSE AESLib-compatible decryption
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, time
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# --- AESLib CBC-compatible decryption ---
def aeslib_decrypt(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ct = unhexlify(ct_hex)

    ecb = AES.new(key, AES.MODE_ECB)
    block_size = 16
    prev = iv
    out = b""

    for i in range(0, len(ct), block_size):
        block = ct[i:i+block_size]
        dec_block = ecb.decrypt(block)
        out_block = bytes(a ^ b for a, b in zip(dec_block, prev))
        out += out_block
        prev = block

    pad = out[-1]
    if 1 <= pad <= 16:
        out = out[:-pad]
    return out

def aes_decrypt_field(cipher_hex: str, key_hex: str):
    if not cipher_hex or ":" not in cipher_hex:
        return None
    try:
        iv_hex, ct_hex = cipher_hex.split(":", 1)
        pt = aeslib_decrypt(iv_hex, ct_hex, key_hex)
        text = pt.decode("utf-8", errors="ignore").strip()
        parts = text.split("::")
        if len(parts) >= 3:
            value, challenge, qkey = parts
        else:
            value, qkey = parts[0], None
        return value, qkey
    except Exception:
        return None, None

# --- ThingSpeak cache ---
CACHE_DURATION = 10
_cache = {"timestamp": 0, "data": None}

def fetch_thingspeak_latest_cached():
    now = time.time()
    if _cache["data"] and (now - _cache["timestamp"]) < CACHE_DURATION:
        return _cache["data"]
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    data = r.json()
    _cache.update({"timestamp": now, "data": data})
    return data

# --- Quantum key endpoint ---
@app.route("/quantum", methods=["GET"])
def api_quantum():
    token = request.args.get("token")
    if token != ESP_AUTH_TOKEN:
        abort(401)
    n = int(request.args.get("n", 16))
    q_hex = get_quantum_challenge(n)
    return jsonify({"ok": True, "quantum_hex": q_hex})

# --- Latest decrypted feed ---
@app.route("/api/latest", methods=["GET"])
def api_latest():
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)

    try:
        data = fetch_thingspeak_latest_cached()
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
    for key, label in fields.items():
        raw = latest.get(key)
        val, qkey = aes_decrypt_field(raw, SERVER_AES_KEY_HEX)
        if label == "Quantum Key":
            decrypted[label] = qkey or val
        elif label == "IR Sensor":
            decrypted[label] = "ON ⚪" if val == "1" else "OFF ⚫"
        elif label == "MAX30100":
            try:
                bpm, spo2 = val.split("/")
                decrypted[label] = {"BPM": int(bpm), "SpO2": float(spo2)}
            except:
                decrypted[label] = val
        else:
            decrypted[label] = val

    return jsonify({
        "ok": True,
        "timestamp": latest.get("created_at"),
        "decrypted": decrypted
    })

# --- Serve frontend ---
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    if not os.path.exists(os.path.join(FRONTEND_FOLDER, path)):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# --- Run server ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"✅ Q-SENSE running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
