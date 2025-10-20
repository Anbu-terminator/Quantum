from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, time
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    os.makedirs(FRONTEND_FOLDER)

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------------- AESLib-Compatible Decryption ----------------
def aeslib_cbc_decrypt(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    """Exact reverse of AESLib.encrypt() on Arduino."""
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ciphertext = unhexlify(ct_hex)

    block_size = 16
    cipher_ecb = AES.new(key, AES.MODE_ECB)

    out = b""
    prev = iv
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        dec_block = cipher_ecb.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(dec_block, prev))
        out += plain_block
        prev = block

    # remove PKCS#7 padding
    pad_len = out[-1]
    if 1 <= pad_len <= 16:
        out = out[:-pad_len]
    return out

def decrypt_field(cipher_hex: str, key_hex: str, label: str):
    result = {"ok": False, "value": None, "quantum": None, "error": None}
    try:
        if ":" not in cipher_hex:
            result["error"] = "invalid_format"
            return result
        iv_hex, ct_hex = cipher_hex.split(":", 1)
        pt_bytes = aeslib_cbc_decrypt(iv_hex, ct_hex, key_hex)
        try:
            text = pt_bytes.decode("utf-8").strip()
        except UnicodeDecodeError:
            text = pt_bytes.decode("latin-1", errors="ignore").strip()

        # expected format: value::challenge::quantum
        parts = text.split("::")
        value = parts[0].strip() if len(parts) >= 1 else None
        quantum = parts[-1].strip() if len(parts) >= 3 else None

        if label.lower() == "quantum key":
            value = quantum or value

        result.update({"ok": True, "value": value, "quantum": quantum})
        return result
    except Exception as e:
        result["error"] = str(e)
        return result


# ---------------- ThingSpeak Cached Fetch ----------------
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


# ---------------- Flask Endpoints ----------------
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
    for fkey, label in fields.items():
        raw = latest.get(fkey)
        if not raw:
            decrypted[label] = "N/A"
            continue
        parsed = decrypt_field(raw, SERVER_AES_KEY_HEX, label)
        val = parsed["value"] if parsed["ok"] else "N/A"

        # Data post-processing
        if label in ["Temperature", "Humidity"]:
            try:
                val = float(val)
            except:
                pass
        elif label == "IR Sensor":
            val = "1" if val == "1" else "0"
        elif label == "MAX30100":
            try:
                bpm, spo2 = val.split("/")
                val = {"BPM": int(bpm), "SpO2": float(spo2)}
            except:
                val = val

        decrypted[label] = val

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })


@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    if not os.path.exists(os.path.join(FRONTEND_FOLDER, path)):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"✅ Q-SENSE running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
