# server.py
import os
import time
import re
from binascii import unhexlify
from typing import Tuple, Optional

import requests
from flask import Flask, jsonify, send_from_directory, request, abort
from Crypto.Cipher import AES

# Load user's config.py which must define:
# THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN
try:
    from config import *
except Exception as e:
    raise RuntimeError("Provide config.py with THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN") from e

# ---------- Basic app + frontend setup ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------- Utils: AESLib-compatible CBC decryption ----------
def aeslib_cbc_decrypt(iv_hex: str, ct_hex: str, key_hex: str) -> bytes:
    """
    Reverse of AESLib.encrypt() behaviour used on the Arduino:
      - AES-128 ECB per-block decrypt, then XOR with previous ciphertext (CBC manual).
      - Remove PKCS#7 padding if present.
    Returns plaintext bytes.
    """
    key = unhexlify(key_hex)
    iv = unhexlify(iv_hex)
    ct = unhexlify(ct_hex)

    cipher_ecb = AES.new(key, AES.MODE_ECB)
    out = bytearray()
    prev = iv
    block_size = 16

    for i in range(0, len(ct), block_size):
        block = ct[i:i+block_size]
        dec = cipher_ecb.decrypt(block)
        plain_block = bytes(a ^ b for a, b in zip(dec, prev))
        out.extend(plain_block)
        prev = block

    # PKCS#7 unpad if valid
    if len(out) == 0:
        return bytes(out)
    pad_len = out[-1]
    if 1 <= pad_len <= 16 and out[-pad_len:] == bytes([pad_len]) * pad_len:
        out = out[:-pad_len]
    return bytes(out)

# Helpers to clean / normalize ciphertext hex
def strip_trailing_iv(ct_hex: str, iv_hex: str) -> str:
    """If ct_hex ends with iv_hex repeated, remove those trailing copies."""
    ct = ct_hex.strip().lower()
    iv = iv_hex.strip().lower()
    if not ct or not iv:
        return ct
    while ct.endswith(iv):
        ct = ct[:-len(iv)]
    return ct

def normalize_cipher_hex(ct_hex: str) -> str:
    s = re.sub(r"[^0-9a-fA-F]", "", ct_hex)
    if len(s) % 2 == 1:
        s = s[:-1]
    # trim to full AES blocks (16 bytes -> 32 hex chars)
    rem = len(s) % 32
    if rem != 0:
        s = s[:-rem]
    return s

# ---------- Heuristic parsing of plaintext ----------
HEX_RE = re.compile(r"[0-9a-fA-F]{32,}")                     # long hex (quantum key)
NUM_RE = re.compile(r"[-+]?\d*\.\d+|\d+")                    # first number (temp/hum/bpm)
BPM_SPO2_RE = re.compile(r"(\d{1,3})\s*/\s*(\d{1,3}(?:\.\d+)?)")  # bpm/spo2

def extract_value_from_plaintext(pt_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Attempts to extract (value, quantum_hex) from plaintext bytes.
    Returns raw string value and quantum hex (if found).
    Uses several fallbacks:
     - split by '::' if present
     - otherwise look for long trailing hex (quantum)
     - attempt to extract numeric tokens if leading bytes contain noise
    """
    # try decode utf-8 first, else latin-1
    try:
        text = pt_bytes.decode("utf-8")
    except Exception:
        text = pt_bytes.decode("latin-1", errors="ignore")

    # Trim NULs and whitespace
    text = text.strip("\x00 \r\n\t")

    # 1) if Arduino-format present, take split
    if "::" in text:
        parts = text.split("::")
        value = parts[0].strip() if len(parts) >= 1 else None
        quantum = parts[-1].strip() if len(parts) >= 3 else None
        return value or None, quantum or None

    # 2) look for a trailing long hex sequence (quantum) and take preceding printable tail as value
    m_hex = HEX_RE.search(text)
    quantum = m_hex.group(0) if m_hex else None
    if quantum:
        # take substring before hex occurrence
        idx = text.find(quantum)
        head = text[:idx].strip()
        # find last printable chunk in head
        printable_tail = re.findall(r"[ -~]+", head)  # ascii printable runs
        value = printable_tail[-1].strip() if printable_tail else None
        return value or None, quantum

    # 3) try BPM/SpO2 pattern anywhere
    m_bs = BPM_SPO2_RE.search(text)
    if m_bs:
        bpm = m_bs.group(1)
        spo2 = m_bs.group(2)
        return f"{bpm}/{spo2}", None

    # 4) fallback: find first number-like substring (useful for temp/hum)
    m_num = NUM_RE.search(text)
    if m_num:
        return m_num.group(0), None

    # 5) final fallback: return visible printable characters if any
    printable = "".join(ch for ch in text if 32 <= ord(ch) <= 126)
    if printable:
        return printable.strip(), None

    return None, None

# ---------- ThingSpeak cached fetch ----------
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

# ---------- Decrypt one field robustly ----------
def decrypt_field_robust(field_hex: str, key_hex: str, label: str):
    """
    Returns dict: {'ok': bool, 'value': <str|None>, 'quantum': <str|None>, 'error': <str|None>}
    """
    out = {"ok": False, "value": None, "quantum": None, "error": None}

    if not field_hex or ":" not in field_hex:
        out["error"] = "invalid_field_format"
        return out

    iv_hex, ct_hex = field_hex.split(":", 1)

    # Observed ThingSpeak sometimes appends IV hex to the end; remove trailing copies
    ct_hex_stripped = strip_trailing_iv(ct_hex, iv_hex)
    ct_norm = normalize_cipher_hex(ct_hex_stripped)

    if not ct_norm:
        out["error"] = "ciphertext_empty_after_normalize"
        return out

    try:
        pt = aeslib_cbc_decrypt(iv_hex, ct_norm, key_hex)
    except Exception as e:
        out["error"] = f"decrypt_exception:{e}"
        return out

    value, quantum = extract_value_from_plaintext(pt)

    # Final cleanups
    if value is not None:
        value = value.strip()
        if value == "":
            value = None
    if quantum is not None:
        quantum = quantum.strip()
        if quantum == "":
            quantum = None

    out.update({"ok": True, "value": value, "quantum": quantum})
    return out

# ---------- Small helpers to turn sensor value types ----------
def parse_numeric(value: Optional[str]) -> Optional[float]:
    if value is None:
        return None
    m = re.search(r"[-+]?\d*\.\d+|\d+", value)
    if not m:
        return None
    try:
        return float(m.group(0))
    except:
        return None

def parse_bpm_spo2(value: Optional[str]):
    if not value:
        return None
    m = re.search(r"(\d{1,3})\s*/\s*(\d{1,3}(?:\.\d+)?)", value)
    if not m:
        return None
    try:
        return {"BPM": int(m.group(1)), "SpO2": float(m.group(2))}
    except:
        return None

# ---------- Flask endpoints ----------
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

        parsed = decrypt_field_robust(raw, SERVER_AES_KEY_HEX, label)
        if not parsed["ok"]:
            out[label] = None
            continue

        val = parsed["value"]
        q = parsed["quantum"]

        # If this is the Quantum Key field, prefer the extracted quantum hex
        if label.lower() == "quantum key":
            out[label] = q or val
            continue

        # Post-process types
        if label in ("Temperature", "Humidity"):
            out[label] = parse_numeric(val)
        elif label == "IR Sensor":
            # normalize to 0/1
            if val is None:
                out[label] = None
            else:
                out[label] = 1 if re.search(r"1", str(val)) else 0
        elif label == "MAX30100":
            parsed_max = parse_bpm_spo2(val)
            out[label] = parsed_max
        else:
            out[label] = val

    return jsonify({"ok": True, "decrypted": out, "timestamp": latest.get("created_at")})

# Serve frontend static files
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# ---------- Run server ----------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Q-SENSE server starting on 0.0.0.0:{port} (frontend: {FRONTEND_FOLDER})")
    app.run(host="0.0.0.0", port=port, debug=False)
