import os
import re
import time
from binascii import unhexlify
import requests
from flask import Flask, jsonify, send_from_directory, request, abort
from Crypto.Cipher import AES

# load config from config.py
try:
    from config import *
except Exception as e:
    raise RuntimeError("Please provide config.py with THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN") from e

CACHE_DURATION = 10
DEBUG = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ===== AES CBC Decrypt (AESLib compatible) =====
def aeslib_cbc_decrypt(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ciphertext = unhexlify(ct_hex)
    cipher_ecb = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    prev = iv
    block_size = 16
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i:i + block_size]
        dec = cipher_ecb.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        out.extend(plain_block)
        prev = block
    if len(out) == 0:
        return bytes(out)
    pad_len = out[-1]
    if 1 <= pad_len <= 16 and out[-pad_len:] == bytes([pad_len]) * pad_len:
        out = out[:-pad_len]
    return bytes(out)

# Remove trailing IV from ciphertext if duplicated
def strip_trailing_iv(ct_hex: str, iv_hex: str) -> str:
    ct_hex = re.sub(r'[^0-9a-fA-F]', '', (ct_hex or ""))
    iv_hex = re.sub(r'[^0-9a-fA-F]', '', (iv_hex or ""))
    while iv_hex and ct_hex.endswith(iv_hex):
        ct_hex = ct_hex[:-len(iv_hex)]
    return ct_hex

def normalize_hex(ct_hex: str) -> str:
    s = re.sub(r'[^0-9a-fA-F]', '', (ct_hex or ""))
    if len(s) % 2 != 0:
        s = s[:-1]
    rem = len(s) % 32
    if rem != 0:
        s = s[:-rem]
    return s

HEX_RE = re.compile(r'[0-9a-fA-F]{16,64}')
FLOAT_RE = re.compile(r'[-+]?\d*\.\d+|\d+')
IR_RE = re.compile(r'\b([01])\b')
BPM_SPO2_RE = re.compile(r'(\d{1,3})\s*/\s*(\d{1,3})')

def extract_value(pt_bytes: bytes, label: str):
    text = pt_bytes.decode('utf-8', errors='ignore').strip()
    if label.lower() == 'quantum key':
        m = HEX_RE.search(text)
        return m.group(0) if m else text
    elif label.lower() == 'temperature' or label.lower() == 'humidity':
        m = FLOAT_RE.search(text)
        return float(m.group(0)) if m else text
    elif label.lower() == 'ir sensor':
        m = IR_RE.search(text)
        return int(m.group(1)) if m else text
    elif label.lower() == 'max30100':
        m = BPM_SPO2_RE.search(text)
        if m:
            return {"BPM": int(m.group(1)), "SpO2": int(m.group(2))}
        return text
    return text

def decrypt_field(field_hex: str, key_hex: str, label: str):
    try:
        if not field_hex or ":" not in field_hex:
            return None
        iv_hex, ct_hex = field_hex.split(":", 1)
        ct_hex = strip_trailing_iv(ct_hex, iv_hex)
        ct_hex = normalize_hex(ct_hex)
        if not ct_hex:
            return None
        pt_bytes = aeslib_cbc_decrypt(iv_hex, ct_hex, key_hex)
        return extract_value(pt_bytes, label)
    except:
        return None

_cache = {"ts": 0, "data": None}

def fetch_thingspeak_latest():
    now = time.time()
    if _cache["data"] and (now - _cache["ts"]) < CACHE_DURATION:
        return _cache["data"]
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    data = r.json()
    _cache.update({"ts": now, "data": data})
    return data

@app.route("/api/latest", methods=["GET"])
def api_latest():
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)
    data = fetch_thingspeak_latest()
    feeds = data.get("feeds", [])
    if not feeds:
        return jsonify({"error": "No feed data"}), 404
    latest = feeds[-1]
    fields_map = {
        "field1": "Quantum Key",
        "field2": "Temperature",
        "field3": "Humidity",
        "field4": "IR Sensor",
        "field5": "MAX30100",
    }
    out = {}
    for fk, label in fields_map.items():
        raw = latest.get(fk)
        out[label] = decrypt_field(raw, SERVER_AES_KEY_HEX, label) or "--"
    return jsonify({"ok": True, "decrypted": out, "timestamp": latest.get("created_at")})

@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Q-SENSE running at 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
