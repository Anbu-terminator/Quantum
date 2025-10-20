import os, time, re, requests
from binascii import unhexlify
from flask import Flask, jsonify, send_from_directory, request, abort
from Crypto.Cipher import AES

# Load config from config.py
try:
    from config import THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN
except Exception as e:
    raise RuntimeError("Please provide config.py with correct keys") from e

CACHE_DURATION = 10
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# AES CBC decrypt compatible with Arduino AESLib
def aes_cbc_decrypt(iv_hex, ct_hex, key_hex):
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ct = unhexlify(ct_hex)
    cipher = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        block = ct[i:i+16]
        dec = cipher.decrypt(block)
        out.extend([a ^ b for a, b in zip(dec, prev)])
        prev = block
    # Remove PKCS#7 padding
    if out and 0 < out[-1] <= 16:
        out = out[:-out[-1]]
    return bytes(out)

def clean_cipher(ct_hex, iv_hex):
    ct = re.sub(r'[^0-9a-fA-F]', '', ct_hex)
    iv = re.sub(r'[^0-9a-fA-F]', '', iv_hex)
    while iv and ct.endswith(iv):
        ct = ct[:-len(iv)]
    rem = len(ct) % 32
    if rem:
        ct = ct[:-rem]
    return ct

def extract_value(pt_bytes, label):
    try:
        txt = pt_bytes.decode('utf-8', errors='ignore').strip()
    except:
        txt = pt_bytes.decode('latin-1', errors='ignore').strip()
    if label.lower() == "quantum key":
        return re.search(r'[0-9a-fA-F]{16,64}', txt).group(0) if re.search(r'[0-9a-fA-F]{16,64}', txt) else txt
    if label.lower() == "max30100":
        m = re.search(r'(\d{1,3})/(\d{1,3})', txt)
        if m:
            return {"BPM": int(m.group(1)), "SpO2": int(m.group(2))}
    if label.lower() in ["temperature","humidity"]:
        m = re.search(r'[-+]?\d*\.?\d+|\d+', txt)
        if m: return float(m.group(0))
    if label.lower() == "ir sensor":
        return int(re.search(r'\b([01])\b', txt).group(1)) if re.search(r'\b([01])\b', txt) else txt
    return txt

def decrypt_field(field_hex, label):
    if not field_hex or ":" not in field_hex:
        return None
    iv_hex, ct_hex = field_hex.split(":", 1)
    ct_hex = clean_cipher(ct_hex, iv_hex)
    if not ct_hex:
        return None
    pt = aes_cbc_decrypt(iv_hex, ct_hex, SERVER_AES_KEY_HEX)
    return extract_value(pt, label)

_cache = {"ts":0, "data":None}

def fetch_latest():
    now = time.time()
    if _cache["data"] and now - _cache["ts"] < CACHE_DURATION:
        return _cache["data"]
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    data = r.json()
    _cache.update({"ts": now, "data": data})
    return data

@app.route("/api/latest")
def api_latest():
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)
    try:
        data = fetch_latest()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    feed = data.get("feeds", [{}])[-1]
    out = {}
    field_map = {
        "field1": "Quantum Key",
        "field2": "Temperature",
        "field3": "Humidity",
        "field4": "IR Sensor",
        "field5": "MAX30100"
    }
    for k, label in field_map.items():
        out[label] = decrypt_field(feed.get(k), label) or "--"
    return jsonify({"ok": True, "decrypted": out, "timestamp": feed.get("created_at")})

@app.route("/", defaults={"path":"index.html"})
@app.route("/<path:path>")
def frontend(path):
    if not os.path.exists(os.path.join(FRONTEND_FOLDER, path)):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Server running on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
