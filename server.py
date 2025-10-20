# server.py
import os
import re
import time
from binascii import unhexlify
import requests
from flask import Flask, jsonify, send_from_directory, request, abort
from Crypto.Cipher import AES

# ========== CONFIG ==========
# Provide these in config.py in same folder:
# THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN
try:
    from config import THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN
except Exception as e:
    raise RuntimeError("Please create config.py with THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN") from e

CACHE_DURATION = 10   # seconds
DEBUG = False         # set True to print debug plaintexts

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ----------------- Helpers: hex cleaning -----------------
def keep_hex(s: str) -> str:
    if not s:
        return ""
    return re.sub(r'[^0-9a-fA-F]', '', s)

def strip_trailing_iv(ct_hex: str, iv_hex: str) -> str:
    """Remove repeated trailing IV hex copies from ct_hex."""
    ct = keep_hex(ct_hex)
    iv = keep_hex(iv_hex)
    while iv and ct.endswith(iv) and len(ct) > len(iv):
        ct = ct[:-len(iv)]
    return ct

def normalize_ct_hex(ct_hex: str) -> str:
    s = keep_hex(ct_hex)
    # make even-length
    if len(s) % 2 != 0:
        s = s[:-1]
    # trim to full AES blocks (16 bytes -> 32 hex chars)
    rem = len(s) % 32
    if rem:
        s = s[:-rem]
    return s

# ----------------- AES decryption variants -----------------
def aes_cbc_standard(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    """Standard AES-CBC using PyCryptodome."""
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ct = unhexlify(ct_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    # strip PKCS#7 if present
    if pt and 1 <= pt[-1] <= 16:
        pad = pt[-1]
        if pt[-pad:] == bytes([pad]) * pad:
            pt = pt[:-pad]
    return pt

def aes_ecb_manual_xor(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    """
    AESLib-style: AES-ECB decrypt per block, then XOR with previous ciphertext block (or IV).
    This replicates the Arduino AESLib approach used by many sketches.
    """
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ct = unhexlify(ct_hex)
    ecb = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    prev = iv
    block_size = 16
    for i in range(0, len(ct), block_size):
        block = ct[i:i + block_size]
        dec = ecb.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        out.extend(plain_block)
        prev = block
    # unpad if looks like PKCS7
    if out and 1 <= out[-1] <= 16:
        pad = out[-1]
        if out[-pad:] == bytes([pad]) * pad:
            out = out[:-pad]
    return bytes(out)

# ----------------- Plaintext extraction rules -----------------
HEX32_RE = re.compile(r'[0-9a-fA-F]{32,64}')
BPM_SPO2_RE = re.compile(r'(\d{1,3})\s*/\s*([0-9]{1,3}(?:\.\d+)?)')
FLOAT_RE = re.compile(r'[-+]?\d*\.\d+|\d+')
IR_RE = re.compile(r'\b([01])\b')

def extract_value_from_plain(pt_bytes: bytes, label: str):
    # prefer latin-1 decode to preserve 1:1 mapping of bytes -> chars
    text = pt_bytes.decode('latin-1', errors='ignore').strip('\x00').strip()
    # If format contains :: use it: value::challenge::quantum
    if "::" in text:
        parts = [p.strip() for p in text.split("::")]
        val_part = parts[0] if len(parts) >= 1 else text
        quantum_part = parts[-1] if len(parts) >= 3 else None
    else:
        val_part = text
        quantum_part = None

    label_l = label.lower()
    if label_l == "quantum key":
        if quantum_part:
            h = keep_hex(quantum_part)
            if len(h) >= 32:
                return h[-32:]
            if h:
                return h
        m = HEX32_RE.search(text)
        if m:
            return m.group(0)[-32:]
        # fallback: last 32 hex chars anywhere
        allh = keep_hex(text)
        return allh[-32:] if len(allh) >= 32 else (allh or None)

    if label_l == "max30100":
        m = BPM_SPO2_RE.search(val_part) or BPM_SPO2_RE.search(text)
        if m:
            try:
                bpm = int(m.group(1))
                spo2 = float(m.group(2))
                return {"BPM": bpm, "SpO2": spo2}
            except:
                pass
        # fallback: two numbers in val_part
        nums = FLOAT_RE.findall(val_part)
        if len(nums) >= 2:
            try:
                return {"BPM": int(float(nums[0])), "SpO2": float(nums[1])}
            except:
                pass
        return None

    if label_l in ("temperature", "humidity"):
        m = FLOAT_RE.search(val_part) or FLOAT_RE.search(text)
        if m:
            try:
                return float(m.group(0))
            except:
                pass
        return None

    if label_l == "ir sensor":
        m = IR_RE.search(val_part) or IR_RE.search(text)
        if m:
            return int(m.group(1))
        return None

    # fallback: printable ASCII run
    printable = ''.join(ch for ch in val_part if 32 <= ord(ch) <= 126)
    if printable:
        return printable.strip()
    printable2 = ''.join(ch for ch in text if 32 <= ord(ch) <= 126)
    return printable2.strip() if printable2 else None

# ----------------- Scoring to choose best decryption -----------------
def score_candidate(value, label):
    """Return a score (higher = better) for how plausible value is for label."""
    if value is None:
        return 0
    label_l = label.lower()
    # quantum key: long hex is great
    if label_l == "quantum key":
        if isinstance(value, str):
            hx = keep_hex(value)
            if len(hx) >= 32:
                return 10
            if len(hx) >= 16:
                return 6
        return 1
    if label_l in ("temperature", "humidity"):
        if isinstance(value, (int, float)):
            v = float(value)
            if label_l == "temperature":
                return 10 if -50 <= v <= 85 else 2
            else:
                return 10 if 0 <= v <= 100 else 2
        return 0
    if label_l == "ir sensor":
        if value in (0, 1) or str(value) in ("0", "1"):
            return 10
        return 0
    if label_l == "max30100":
        if isinstance(value, dict) and "BPM" in value and "SpO2" in value:
            bpm = value["BPM"]
            spo2 = value["SpO2"]
            if 30 <= int(bpm) <= 220 and 50.0 <= float(spo2) <= 100.0:
                return 10
            if 0 <= int(bpm) <= 400:
                return 5
        return 0
    # fallback: short printable string is okay
    if isinstance(value, str) and len(value) > 0:
        return 4
    return 0

# ----------------- Decrypt field with robust selection -----------------
def decrypt_field(field_hex: str, key_hex: str, label: str):
    """
    Try both standard CBC and AESLib-style (ECB+XOR) decryption and pick the best.
    Returns typed value or None.
    """
    if not field_hex or ":" not in field_hex:
        return None
    iv_hex, ct_hex = field_hex.split(":", 1)
    iv_hex = keep_hex(iv_hex)
    # Remove repeated IV appended to ciphertext
    ct_hex = strip_trailing_iv(ct_hex, iv_hex)
    ct_hex = normalize_ct_hex(ct_hex)
    if not iv_hex or not ct_hex:
        if DEBUG:
            print("empty iv/ct after cleaning", iv_hex, ct_hex)
        return None

    candidates = []
    # attempt 1: standard AES-CBC
    try:
        pt_std = aes_cbc_standard(iv_hex, ct_hex, key_hex)
        val_std = extract_value_from_plain(pt_std, label)
        candidates.append(("cbc", val_std, pt_std))
        if DEBUG:
            print("CBC plaintext:", repr(pt_std[:120]))
    except Exception as e:
        if DEBUG:
            print("CBC decrypt failed:", e)

    # attempt 2: AESLib-style (ECB + XOR)
    try:
        pt_lib = aes_ecb_manual_xor(iv_hex, ct_hex, key_hex)
        val_lib = extract_value_from_plain(pt_lib, label)
        candidates.append(("ecb_xor", val_lib, pt_lib))
        if DEBUG:
            print("ECB-XOR plaintext:", repr(pt_lib[:120]))
    except Exception as e:
        if DEBUG:
            print("ECB-XOR failed:", e)

    if not candidates:
        return None

    # Score candidates
    best = None
    best_score = -1
    for method, val, pt in candidates:
        sc = score_candidate(val, label)
        if DEBUG:
            print("candidate", method, "score", sc, "val", val)
        if sc > best_score:
            best_score = sc
            best = (method, val, pt)

    # if best still has score 0, choose CBC candidate if exists, else first
    if best_score <= 0:
        for method, val, pt in candidates:
            if method == "cbc":
                return val
        return candidates[0][1]

    return best[1]

# ----------------- ThingSpeak fetch + cache -----------------
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

# ----------------- Flask endpoints -----------------
@app.route("/api/latest", methods=["GET"])
def api_latest():
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
        val = decrypt_field(raw, SERVER_AES_KEY_HEX, label)
        # normalize: quantum key string, others typed or None
        if label == "Quantum Key":
            out[label] = val if isinstance(val, str) else (val or None)
        else:
            out[label] = val if val is not None else None

    return jsonify({"ok": True, "decrypted": out, "timestamp": latest.get("created_at")})

# Serve frontend
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
    app.run(host="0.0.0.0", port=port, debug=False)
