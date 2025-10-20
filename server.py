# server.py
import os
import re
import time
from binascii import unhexlify

import requests
from flask import Flask, jsonify, send_from_directory, request, abort
from Crypto.Cipher import AES

# load config from config.py (must provide these variables)
try:
    from config import *
except Exception as e:
    raise RuntimeError("Please provide config.py with THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN") from e

# ----- settings -----
CACHE_DURATION = 10  # seconds
DEBUG = False

# ----- flask / frontend setup -----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ===== AESLib-compatible CBC decrypt (reverse of AESLib.encrypt) =====
def aeslib_cbc_decrypt(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    """
    Exact inverse of AESLib.encrypt used on Arduino:
    - key_hex, iv_hex and ct_hex are hex strings (no 0x)
    - returns plaintext bytes with PKCS#7 padding removed
    """
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

    # PKCS#7 unpad (safe)
    if len(out) == 0:
        return bytes(out)
    pad_len = out[-1]
    if 1 <= pad_len <= 16 and pad_len <= len(out):
        if out[-pad_len:] == bytes([pad_len]) * pad_len:
            out = out[:-pad_len]
    return bytes(out)

# ----- Helpers for ThingSpeak ciphertext cleaning -----
def strip_trailing_iv_from_cipher(ct_hex: str, iv_hex: str) -> str:
    """If ciphertext hex ends with repeated iv hex blocks, strip them."""
    if not ct_hex or not iv_hex:
        return ct_hex or ""
    ct = ct_hex.strip().lower()
    iv = iv_hex.strip().lower()
    # remove non-hex chars
    ct = re.sub(r'[^0-9a-f]', '', ct)
    iv = re.sub(r'[^0-9a-f]', '', iv)
    while iv and ct.endswith(iv):
        ct = ct[:-len(iv)]
    return ct

def normalize_cipher_hex(ct_hex: str) -> str:
    """Sanitize hex string: keep hex chars, make even length, trim to block size."""
    s = re.sub(r'[^0-9a-fA-F]', '', (ct_hex or ""))
    if len(s) % 2 != 0:
        s = s[:-1]
    # ensure ciphertext length is multiple of 16 bytes (32 hex chars)
    rem = len(s) % (16 * 2)
    if rem != 0:
        s = s[: -rem]
    return s

# ===== Value extraction from decrypted bytes =====
# We'll attempt multiple strategies to reliably extract sensor values from decrypted bytes:
# - find MAX30100 pattern: bpm/spo2 (e.g. "72/98.5")
# - find float-like number for temperature/humidity
# - find standalone "0" or "1" for IR
# - find a long hex string for quantum key
HEX_32_RE = re.compile(r'[0-9a-fA-F]{24,64}')  # quantum key-like
BPM_SPO2_RE = re.compile(r'(\d{1,3})\s*/\s*([0-9]{1,3}(?:\.[0-9]+)?)')
FLOAT_RE = re.compile(r'[-+]?\d*\.\d+|\d+')
IR_RE = re.compile(r'\b([01])\b')

def extract_value_from_plaintext(pt_bytes: bytes, label: str):
    """
    Given plaintext bytes, extract the likely value for the given label.
    Returns (extracted_value_as_string_or_None, raw_text_for_debug)
    """
    # First try safe decodes:
    try:
        text_utf8 = pt_bytes.decode('utf-8', errors='ignore')
    except Exception:
        text_utf8 = ''
    text_l1 = pt_bytes.decode('latin-1', errors='ignore')
    # Prefer the representation that contains the separator :: if present
    text = text_utf8 if '::' in text_utf8 else text_l1
    text = text.strip()

    # If label is Quantum Key, try extracting a long hex substring
    if label.lower() == 'quantum key':
        m = HEX_32_RE.search(text)
        if m:
            return m.group(0), text

    # MAX30100 (bpm/spo2)
    if label.lower() == 'max30100':
        m = BPM_SPO2_RE.search(text)
        if m:
            bpm = m.group(1)
            spo2 = m.group(2)
            return f"{bpm}/{spo2}", text

    # Temperature / Humidity: find first float-like number
    if label.lower() in ('temperature', 'humidity'):
        m = FLOAT_RE.search(text)
        if m:
            return m.group(0), text

    # IR Sensor: look for '0' or '1'
    if label.lower() == 'ir sensor':
        m = IR_RE.search(text)
        if m:
            return m.group(1), text

    # Fallbacks:
    # - If text includes "::", split and take first part
    if '::' in text:
        parts = text.split('::')
        return parts[0].strip(), text
    # - find first printable run of ascii characters (letters/digits/./-/)
    printable = ''.join(ch for ch in text if 32 <= ord(ch) <= 126)
    if printable:
        return printable.strip(), text

    # Nothing found
    return None, text

# ===== Decrypt one TS field (iv:ct) and parse value =====
def decrypt_thingspeak_field(field_hex: str, key_hex: str, label: str):
    """
    Returns dict: {"ok": True/False, "value": <extracted or None>, "raw": <decoded text>, "error": <str>}
    """
    result = {"ok": False, "value": None, "raw": None, "error": None}
    try:
        if not field_hex or ":" not in field_hex:
            result["error"] = "missing_field_or_iv"
            return result

        iv_hex, ct_hex = field_hex.split(":", 1)
        # strip trailing IV copies
        ct_hex = strip_trailing_iv_from_cipher(ct_hex, iv_hex)
        ct_hex = normalize_cipher_hex(ct_hex)
        if not ct_hex:
            result["error"] = "ciphertext_empty_after_clean"
            return result

        # perform AESLib-style decrypt
        pt_bytes = aeslib_cbc_decrypt(iv_hex, ct_hex, key_hex)

        # Extract
        val, raw_text = extract_value_from_plaintext(pt_bytes, label)
        result.update({"ok": True, "value": val, "raw": raw_text})
        return result
    except Exception as e:
        result["error"] = f"decrypt_exception:{e}"
        return result

# ===== ThingSpeak cached fetch =====
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

# ===== Flask endpoints =====
@app.route("/quantum", methods=["GET"])
def api_quantum():
    token = request.args.get("token")
    if token != ESP_AUTH_TOKEN:
        abort(401)
    n = int(request.args.get("n", 16))
    return jsonify({"ok": True, "quantum_hex": get_quantum_challenge(n)})

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
    debug_info = {} if DEBUG else None

    for fk, label in fields_map.items():
        raw = latest.get(fk)
        if not raw:
            out[label] = None
            if DEBUG:
                debug_info[label] = {"error": "no_field"}
            continue
        parsed = decrypt_thingspeak_field(raw, SERVER_AES_KEY_HEX, label)
        if not parsed.get("ok"):
            out[label] = None
            if DEBUG:
                debug_info[label] = {"error": parsed.get("error")}
            continue

        val = parsed.get("value")
        raw_text = parsed.get("raw")

        # Post-process to structured values
        if label in ("Temperature", "Humidity"):
            try:
                out[label] = float(val) if val is not None else None
            except Exception:
                out[label] = None
        elif label == "IR Sensor":
            if val is None:
                out[label] = None
            else:
                out[label] = 1 if str(val).strip() == "1" else 0
        elif label == "MAX30100":
            if isinstance(val, str) and "/" in val:
                try:
                    bpm_s, spo2_s = val.split("/", 1)
                    out[label] = {"BPM": int(float(bpm_s)), "SpO2": float(spo2_s)}
                except Exception:
                    out[label] = None
            else:
                out[label] = None
        else:  # Quantum Key or fallback
            out[label] = val

        if DEBUG:
            debug_info[label] = {"raw_text": raw_text, "extracted": val}

    resp = {"ok": True, "decrypted": out, "timestamp": latest.get("created_at")}
    if DEBUG:
        resp["debug"] = debug_info
    return jsonify(resp)

# serve frontend
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# --- run ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    if DEBUG:
        print("DEBUG mode ON")
    print(f"Q-SENSE starting on 0.0.0.0:{port} (frontend: {FRONTEND_FOLDER})")
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
