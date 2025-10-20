# server.py
import os
import re
import time
from binascii import unhexlify
import requests
from flask import Flask, jsonify, send_from_directory, request, abort
from Crypto.Cipher import AES

# Load config values from config.py in same folder.
# Ensure config.py defines:
# THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN
try:
    from config import THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN
except Exception as e:
    raise RuntimeError("Please provide config.py with THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN") from e

CACHE_DURATION = 10       # seconds cache for ThingSpeak calls
DEBUG = False             # set True to get server-side debug prints

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------------- AESLib-compatible decryption ----------------
def aeslib_cbc_decrypt(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    """
    Reverse of AESLib.encrypt on Arduino:
      - decrypt each block with AES-ECB
      - XOR decrypted block with previous ciphertext block (or IV for first block)
      - remove PKCS#7 padding
    Returns plaintext bytes.
    """
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ct = unhexlify(ct_hex)

    ecb = AES.new(key, AES.MODE_ECB)
    block_size = 16
    out = bytearray()
    prev = iv

    for i in range(0, len(ct), block_size):
        block = ct[i:i + block_size]
        dec_block = ecb.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(dec_block, prev))
        out.extend(plain_block)
        prev = block

    # PKCS#7 unpad if valid
    if len(out) == 0:
        return bytes(out)
    pad_len = out[-1]
    if 1 <= pad_len <= 16 and pad_len <= len(out):
        if out[-pad_len:] == bytes([pad_len]) * pad_len:
            out = out[:-pad_len]
    return bytes(out)

# ---------------- hex cleanup utilities ----------------
def keep_hex(s: str) -> str:
    if not s:
        return ""
    return re.sub(r'[^0-9a-fA-F]', '', s)

def strip_trailing_iv(ct_hex: str, iv_hex: str) -> str:
    """Remove repeated trailing IV hex occurrences from ciphertext hex."""
    ct = keep_hex(ct_hex)
    iv = keep_hex(iv_hex)
    if not ct:
        return ""
    # repeatedly remove the final iv hex if it repeats
    while iv and ct.endswith(iv) and len(ct) > len(iv):
        ct = ct[:-len(iv)]
    return ct

def normalize_ct_hex(ct_hex: str) -> str:
    """Trim non-hex chars, ensure even length and multiple of 16 bytes (32 hex chars)."""
    s = keep_hex(ct_hex)
    if len(s) % 2 != 0:
        s = s[:-1]
    # trim to full AES blocks
    rem = len(s) % 32
    if rem:
        s = s[:-rem]
    return s

# ---------------- plaintext extraction ----------------
# Regex patterns
HEX32_RE = re.compile(r'[0-9a-fA-F]{32,64}')
BPM_SPO2_RE = re.compile(r'(\d{1,3})\s*/\s*(\d{1,3}(?:\.\d+)?)')
FLOAT_RE = re.compile(r'[-+]?\d*\.\d+|\d+')
IR_RE = re.compile(r'\b([01])\b')

def extract_from_plain(pt_bytes: bytes, label: str):
    """
    Given plaintext bytes (latin-1 representation preserved), extract value for label.
    Return typed value:
      - Temperature/Humidity -> float
      - IR Sensor -> int 0/1
      - MAX30100 -> dict {"BPM":int, "SpO2":float}
      - Quantum Key -> hex string (last 32 hex chars preferred)
      - fallback -> cleaned printable string or None
    """
    # decode to latin-1 to preserve bytes
    text = pt_bytes.decode('latin-1', errors='ignore')
    # Trim NULs and many control bytes
    text_stripped = text.strip('\x00').strip()

    # If Arduino-style separator present, prefer parsing parts
    if "::" in text_stripped:
        parts = [p for p in text_stripped.split("::")]
        # value is first part, quantum could be last
        candidate_value = parts[0].strip()
        candidate_quantum = parts[-1].strip() if len(parts) >= 3 else None
    else:
        candidate_value = text_stripped
        candidate_quantum = None

    # Quantum Key: prefer explicit quantum part; else search for last long hex
    if label.lower() == "quantum key":
        if candidate_quantum:
            hx = keep_hex(candidate_quantum)
            if len(hx) >= 32:
                return hx[-32:]
            if hx:
                return hx
        m = HEX32_RE.search(text_stripped)
        if m:
            return m.group(0)[-32:]
        # fallback: last 32 hex characters if exist in entire text
        allhex = keep_hex(text_stripped)
        return allhex[-32:] if len(allhex) >= 32 else (allhex or None)

    # MAX30100: find bpm/spo2 in value or full text
    if label.lower() == "max30100":
        # first try candidate_value
        m = BPM_SPO2_RE.search(candidate_value)
        if not m:
            m = BPM_SPO2_RE.search(text_stripped)
        if m:
            try:
                bpm = int(m.group(1))
                spo2 = float(m.group(2))
                return {"BPM": bpm, "SpO2": spo2}
            except Exception:
                pass
        # fallback: maybe present as "bpm/spo2" with non-standard separators
        nums = FLOAT_RE.findall(candidate_value)
        if len(nums) >= 2:
            try:
                return {"BPM": int(float(nums[0])), "SpO2": float(nums[1])}
            except:
                pass
        return None

    # Temperature / Humidity: first float in candidate_value or text
    if label.lower() in ("temperature", "humidity"):
        m = FLOAT_RE.search(candidate_value)
        if not m:
            m = FLOAT_RE.search(text_stripped)
        if m:
            try:
                return float(m.group(0))
            except:
                pass
        return None

    # IR Sensor: look for standalone 0 or 1 in candidate_value then full text
    if label.lower() == "ir sensor":
        m = IR_RE.search(candidate_value)
        if not m:
            m = IR_RE.search(text_stripped)
        if m:
            return int(m.group(1))
        return None

    # Fallback: return printable substring (ASCII-range) of candidate_value or full text
    printable = ''.join(ch for ch in candidate_value if 32 <= ord(ch) <= 126)
    if printable:
        return printable.strip()
    printable2 = ''.join(ch for ch in text_stripped if 32 <= ord(ch) <= 126)
    return printable2.strip() if printable2 else None

# ---------------- decrypt and parse ThingSpeak field ----------------
def decrypt_field(field_hex: str, key_hex: str, label: str):
    """Main entry: given 'iv:ct' hex string (possibly ct has IV appended), return typed value or None."""
    if not field_hex or ":" not in field_hex:
        return None
    iv_hex, ct_hex = field_hex.split(":", 1)
    iv_hex = keep_hex(iv_hex)
    ct_hex = strip_trailing_iv(ct_hex, iv_hex)   # remove repeated trailing IV
    ct_hex = normalize_ct_hex(ct_hex)
    if not iv_hex or not ct_hex:
        if DEBUG:
            print("cleaning resulted empty iv/ct", iv_hex, ct_hex)
        return None
    try:
        pt_bytes = aeslib_cbc_decrypt(iv_hex, ct_hex, key_hex)
    except Exception as e:
        if DEBUG:
            print("decrypt exception:", e)
        return None
    return extract_from_plain(pt_bytes, label)

# ---------------- ThingSpeak cached fetch ----------------
_cache = {"ts": 0, "data": None}

def fetch_thingspeak_latest_cached():
    now = time.time()
    if _cache["data"] and (now - _cache["ts"]) < CACHE_DURATION:
        return _cache["data"]
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=12)
    r.raise_for_status()
    data = r.json()
    _cache.update({"ts": now, "data": data})
    return data

# ---------------- Flask routes ----------------
@app.route("/api/latest", methods=["GET"])
def api_latest():
    # simple auth (used by your frontend)
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)
    try:
        data = fetch_thingspeak_latest_cached()
    except Exception as e:
        return jsonify({"ok": False, "error": f"ThingSpeak fetch failed: {e}"}), 500

    feeds = data.get("feeds", [])
    if not feeds:
        return jsonify({"ok": False, "error": "No feed data"}), 404

    latest = feeds[-1]
    fields = {
        "field1": "Quantum Key",
        "field2": "Temperature",
        "field3": "Humidity",
        "field4": "IR Sensor",
        "field5": "MAX30100",
    }

    out = {}
    for fk, label in fields.items():
        raw = latest.get(fk)
        val = decrypt_field(raw, SERVER_AES_KEY_HEX, label)
        # If quantum key, ensure string
        if label == "Quantum Key":
            out[label] = val if isinstance(val, str) else (val or "--")
        else:
            out[label] = val if val is not None else None

    return jsonify({"ok": True, "decrypted": out, "timestamp": latest.get("created_at")})

# Serve frontend static files
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    if not os.path.exists(os.path.join(FRONTEND_FOLDER, path)):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# Run
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Q-SENSE server running at http://0.0.0.0:{port} (frontend: {FRONTEND_FOLDER})")
    app.run(host="0.0.0.0", port=port, debug=DEBUG)
