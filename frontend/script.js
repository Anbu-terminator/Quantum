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

# ===== AESLib-compatible decrypt =====
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

def strip_trailing_iv_from_cipher(ct_hex: str, iv_hex: str) -> str:
    if not ct_hex or not iv_hex:
        return ct_hex or ""
    ct = re.sub(r'[^0-9a-f]', '', ct_hex.strip().lower())
    iv = re.sub(r'[^0-9a-f]', '', iv_hex.strip().lower())
    while iv and ct.endswith(iv):
        ct = ct[:-len(iv)]
    return ct

def normalize_cipher_hex(ct_hex: str) -> str:
    s = re.sub(r'[^0-9a-fA-F]', '', (ct_hex or ""))
    if len(s) % 2 != 0:
        s = s[:-1]
    rem = len(s) % (16 * 2)
    if rem != 0:
        s = s[:-rem]
    return s

HEX_32_RE = re.compile(r'[0-9a-fA-F]{24,64}')
BPM_SPO2_RE = re.compile(r'(\d{1,3})\s*/\s*([0-9]{1,3}(?:\.[0-9]+)?)')
FLOAT_RE = re.compile(r'[-+]?\d*\.\d+|\d+')
IR_RE = re.compile(r'\b([01])\b')

def extract_value_from_plaintext(pt_bytes: bytes, label: str):
    try:
        text_utf8 = pt_bytes.decode('utf-8', errors='ignore')
    except Exception:
        text_utf8 = ''
    text_l1 = pt_bytes.decode('latin-1', errors='ignore')
    text = text_utf8 if '::' in text_utf8 else text_l1
    text = text.strip()

    if label.lower() == 'quantum key':
        m = HEX_32_RE.search(text)
        if m:
            return m.group(0), text
    if label.lower() == 'max30100':
        m = BPM_SPO2_RE.search(text)
        if m:
            return f"{m.group(1)}/{m.group(2)}", text
    if label.lower() in ('temperature', 'humidity'):
        m = FLOAT_RE.search(text)
        if m:
            return m.group(0), text
    if label.lower() == 'ir sensor':
        m = IR_RE.search(text)
        if m:
            return m.group(1), text
    if '::' in text:
        parts = text.split('::')
        return parts[0].strip(), text
    printable = ''.join(ch for ch in text if 32 <= ord(ch) <= 126)
    if printable:
        return printable.strip(), text
    return None, text

def decrypt_thingspeak_field(field_hex: str, key_hex: str, label: str):
    result = {"ok": False, "value": None, "raw": None, "error": None}
    try:
        if not field_hex or ":" not in field_hex:
            result["error"] = "missing_field_or_iv"
            return result
        iv_hex, ct_hex = field_hex.split(":", 1)
        ct_hex = strip_trailing_iv_from_cipher(ct_hex, iv_hex)
        ct_hex = normalize_cipher_hex(ct_hex)
        if not ct_hex:
            result["error"] = "ciphertext_empty_after_clean"
            return result
        pt_bytes = aeslib_cbc_decrypt(iv_hex, ct_hex, key_hex)
        val, raw_text = extract_value_from_plaintext(pt_bytes, label)
        result.update({"ok": True, "value": val, "raw": raw_text})
        return result
    except Exception as e:
        result["error"] = f"decrypt_exception:{e}"
        return result

_cache = {"ts": 0, "data": None}

def fetch_thingspeak_latest_cached():
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
    try:
        data = fetch_thingspeak_latest_cached()
    except Exception as e:
        return jsonify({"error": f"ThingSpeak fetch failed: {e}"}), 500
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
        if not raw:
            out[label] = "--"
            continue
        parsed = decrypt_thingspeak_field(raw, SERVER_AES_KEY_HEX, label)
        val = parsed.get("value")
        if not parsed.get("ok") or val is None:
            out[label] = "--"
            continue
        # ensure all values are strings for frontend
        out[label] = str(val)
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
