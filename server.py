# server.py — ready to copy/paste
import os
import time
import re
from binascii import unhexlify

import requests
from flask import Flask, jsonify, send_from_directory, request, abort
from Crypto.Cipher import AES

# ---- config (must be supplied in your config.py) ----
# from config import *
# Expected config variables used below:
# THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN
try:
    from config import *
except Exception as e:
    raise RuntimeError("Please provide config.py with THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN") from e

# ---- small flags ----
DEBUG = False  # set True while debugging locally

# ---- Flask / frontend setup ----
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR  # fallback

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ================ AESLib-compatible CBC decrypt (Arduino AESLib) ================
def aeslib_cbc_decrypt(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    """
    Reverse of AESLib.encrypt() behaviour:
      - key_hex and iv_hex are hex strings (no 0x)
      - ct_hex is ciphertext hex (no 0x)
    Returns plaintext bytes (padding still present — caller must strip).
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
        # CBC decryption: P = AES-1(C) XOR Prev
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        out.extend(plain_block)
        prev = block

    # strip PKCS#7 padding if valid
    if len(out) == 0:
        return bytes(out)
    pad_len = out[-1]
    if 1 <= pad_len <= 16 and pad_len <= len(out):
        # basic padding safety check
        if out[-pad_len:] == bytes([pad_len]) * pad_len:
            out = out[:-pad_len]
    return bytes(out)

# Helper: remove trailing copies of IV hex from ciphertext hex (observed in your ThingSpeak)
def strip_trailing_iv_from_cipher(ct_hex: str, iv_hex: str) -> str:
    """If ciphertext hex ends with the IV hex (one or multiple times), strip those trailing copies."""
    ct = ct_hex.strip().lower()
    iv = iv_hex.strip().lower()
    if not iv or not ct:
        return ct
    # Trim repeats of iv at the end
    while ct.endswith(iv):
        ct = ct[: -len(iv)]
    return ct

# Helper: sanitize / normalize ct hex to even length and multiple-of-blocksize
def normalize_cipher_hex(ct_hex: str):
    s = re.sub(r"[^0-9a-fA-F]", "", ct_hex)
    # drop trailing half-byte if odd length
    if len(s) % 2 != 0:
        s = s[:-1]
    # ensure byte-length is multiple of blocksize (16 bytes => 32 hex chars)
    rem = len(s) % (16 * 2)
    if rem != 0:
        # trim off the leftover (safer than padding unknown data)
        s = s[: -rem]
    return s

# Decrypt one ThingSpeak field (iv:ct) and parse Arduino format value::challenge::quantum
def decrypt_field(field_hex: str, key_hex: str, label: str):
    result = {"ok": False, "value": None, "quantum": None, "error": None}
    try:
        if ":" not in field_hex:
            result["error"] = "missing_iv_separator"
            return result

        iv_hex, ct_hex = field_hex.split(":", 1)
        if DEBUG:
            print("raw iv_hex:", iv_hex[:64], "...", "raw ct_hex len:", len(ct_hex))

        # Observed ThingSpeak payloads include the IV hex appended to the ciphertext.
        # Strip trailing repeats of the IV if present.
        ct_hex = strip_trailing_iv_from_cipher(ct_hex, iv_hex)
        if DEBUG and ct_hex != "":
            print("ct_hex after stripping trailing iv (len):", len(ct_hex))

        # Normalize (remove non-hex chars, ensure proper block alignment)
        ct_hex = normalize_cipher_hex(ct_hex)
        if len(ct_hex) == 0:
            result["error"] = "ciphertext_empty_after_clean"
            return result

        # Decrypt blocks
        pt_bytes = aeslib_cbc_decrypt(iv_hex, ct_hex, key_hex)

        # Try decoding intelligently:
        # 1) try utf-8 directly (expected normal ASCII),
        # 2) fallback to latin-1 (preserves bytes -> 1:1 mapping) if utf8 not containing separators.
        text = None
        try:
            text = pt_bytes.decode("utf-8")
        except Exception:
            text = pt_bytes.decode("latin-1", errors="ignore")

        # If we don't see the Arduino separator, try a latin-1 fallback explicitly
        if "::" not in text:
            text_l1 = pt_bytes.decode("latin-1", errors="ignore")
            if "::" in text_l1:
                text = text_l1

        text = text.strip()

        # Expecting format: value::challenge::quantum_hex
        parts = text.split("::")
        value = parts[0].strip() if len(parts) >= 1 else None
        quantum = parts[-1].strip() if len(parts) >= 3 else None

        if label.lower() == "quantum key":
            # for field1 we prefer showing the actual quantum hex
            value = quantum or value

        result.update({"ok": True, "value": value, "quantum": quantum})
        if DEBUG:
            print(f"DECRYPT {label}: text={text!r}, value={value!r}, quantum={quantum!r}")
        return result

    except Exception as e:
        result["error"] = f"decrypt_exception:{e}"
        return result

# ================ ThingSpeak cached fetch =================
CACHE_DURATION = 10  # seconds
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

# ------------ small helpers to parse numeric fields -------------
def extract_first_number(s):
    if s is None:
        return None
    m = re.search(r"[-+]?\d*\.\d+|\d+", s)
    return m.group(0) if m else None

def to_float_safe(s):
    n = extract_first_number(s)
    try:
        return float(n) if n is not None else None
    except Exception:
        return None

def to_int_safe(s):
    n = extract_first_number(s)
    try:
        return int(float(n)) if n is not None else None
    except Exception:
        return None

# ================= Flask endpoints =================
@app.route("/quantum", methods=["GET"])
def api_quantum():
    token = request.args.get("token")
    if token != ESP_AUTH_TOKEN:
        abort(401)
    n = int(request.args.get("n", 16))
    q = get_quantum_challenge(n)
    return jsonify({"ok": True, "quantum_hex": q})

@app.route("/api/latest", methods=["GET"])
def api_latest():
    # simple auth for ESP/frontend
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
    for fkey, label in fields_map.items():
        raw = latest.get(fkey)
        if not raw:
            out[label] = None
            continue
        parsed = decrypt_field(raw, SERVER_AES_KEY_HEX, label)
        if not parsed.get("ok"):
            out[label] = None
            if DEBUG:
                out[f"{label}_error"] = parsed.get("error")
            continue

        val = parsed.get("value")

        # Post-process into structured types:
        if label in ("Temperature", "Humidity"):
            val_num = to_float_safe(val)
            out[label] = val_num
        elif label == "IR Sensor":
            # normalize to integer 0/1 or None
            if val is None:
                out[label] = None
            else:
                out[label] = 1 if re.search(r"1", str(val)) else 0
        elif label == "MAX30100":
            # expected "bpm/spo2"
            if isinstance(val, str) and "/" in val:
                try:
                    bpm_s, spo2_s = val.split("/", 1)
                    bpm = to_int_safe(bpm_s)
                    spo2 = to_float_safe(spo2_s)
                    out[label] = {"BPM": bpm, "SpO2": spo2}
                except Exception:
                    out[label] = None
            else:
                out[label] = None
        else:  # Quantum Key or fallback
            out[label] = val

    return jsonify({
        "ok": True,
        "decrypted": out,
        "timestamp": latest.get("created_at")
    })

# Serve frontend (static)
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
        print("DEBUG mode enabled")
    print(f"Q-SENSE starting on 0.0.0.0:{port} (frontend: {FRONTEND_FOLDER})")
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
