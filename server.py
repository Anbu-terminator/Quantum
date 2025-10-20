# server.py – FINAL DECRYPTION FIXED VERSION
import os, re, time, requests
from binascii import unhexlify
from flask import Flask, jsonify, request, send_from_directory, abort
from Crypto.Cipher import AES

# ================== CONFIG ==================
try:
    from config import THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY, SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN
except Exception as e:
    raise RuntimeError("Missing config.py with keys!") from e

CACHE_DURATION = 8
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ========== Helpers ==========
def keep_hex(s): return re.sub(r'[^0-9a-fA-F]', '', s or "")
def normalize_ct_hex(s):
    s = keep_hex(s)
    if len(s) % 2: s = s[:-1]
    rem = len(s) % 32
    if rem: s = s[:-rem]
    return s

def strip_iv_tail(ct_hex, iv_hex):
    ct, iv = keep_hex(ct_hex), keep_hex(iv_hex)
    while iv and ct.endswith(iv) and len(ct) > len(iv):
        ct = ct[:-len(iv)]
    return ct

# ========== AES ==========
def aes_cbc(iv, ct, key_hex):
    key = unhexlify(key_hex)
    ivb, ctb = unhexlify(iv), unhexlify(ct)
    cipher = AES.new(key, AES.MODE_CBC, ivb)
    pt = cipher.decrypt(ctb)
    pad = pt[-1]
    if pad <= 16 and pt.endswith(bytes([pad]) * pad):
        pt = pt[:-pad]
    return pt

def aes_ecb_xor(iv, ct, key_hex):
    key = unhexlify(key_hex)
    ivb, ctb = unhexlify(iv), unhexlify(ct)
    ecb = AES.new(key, AES.MODE_ECB)
    out, prev = bytearray(), ivb
    for i in range(0, len(ctb), 16):
        blk = ctb[i:i+16]
        dec = ecb.decrypt(blk)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = blk
    pad = out[-1]
    if pad <= 16 and out.endswith(bytes([pad]) * pad):
        out = out[:-pad]
    return bytes(out)

# ========== Value Extraction ==========
FLOAT_RE = re.compile(r'[-+]?\d*\.\d+|\d+')

def extract_value(pt, label):
    txt = pt.decode('latin-1', 'ignore').strip('\x00').strip()
    val, quantum = txt, None
    if "::" in txt:
        parts = [p.strip() for p in txt.split("::")]
        val, quantum = parts[0], parts[-1]

    lbl = label.lower()

    if lbl == "quantum key":
        h = keep_hex(quantum or val)
        if len(h) >= 32: return h[-32:]
        return h or None

    if lbl in ("temperature", "humidity"):
        m = FLOAT_RE.search(val)
        return float(m.group()) if m else None

    if lbl == "ir sensor":
        digits = re.findall(r'[01]', val)
        return int(digits[0]) if digits else None

    if lbl == "max30100":
        cleaned = re.sub(r'[^0-9./]', '', val)
        if '/' in cleaned:
            try:
                bpm, spo2 = cleaned.split('/')
                return {"BPM": int(float(bpm)), "SpO2": float(spo2)}
            except: return None
        nums = FLOAT_RE.findall(cleaned)
        if len(nums) >= 2:
            return {"BPM": int(float(nums[0])), "SpO2": float(nums[1])}
        return None

    return ''.join(ch for ch in val if 32 <= ord(ch) <= 126).strip() or None

# ========== Decrypt Field ==========
def decrypt_field(field, key_hex, label):
    if not field or ":" not in field: return None
    iv, ct = field.split(":", 1)
    iv, ct = keep_hex(iv), normalize_ct_hex(strip_iv_tail(ct, iv))
    if not iv or not ct: return None

    best = None
    for method in ("cbc", "ecb"):
        try:
            pt = aes_cbc(iv, ct, key_hex) if method == "cbc" else aes_ecb_xor(iv, ct, key_hex)
            val = extract_value(pt, label)
            if val is not None:
                best = val
                break
        except Exception as e:
            continue
    return best

# ========== ThingSpeak ==========
_cache = {"ts": 0, "data": None}
def fetch_latest():
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

# ========== Routes ==========
@app.route("/api/latest")
def latest():
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)
    try:
        feeds = fetch_latest().get("feeds", [])
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    if not feeds: return jsonify({"ok": False, "error": "No data"}), 404

    latest = feeds[-1]
    mapping = {
        "field1": "Quantum Key",
        "field2": "Temperature",
        "field3": "Humidity",
        "field4": "IR Sensor",
        "field5": "MAX30100"
    }

    out = {}
    for f, label in mapping.items():
        val = decrypt_field(latest.get(f), SERVER_AES_KEY_HEX, label)
        out[label] = val

    return jsonify({"ok": True, "decrypted": out, "timestamp": latest.get("created_at")})

@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve(path):
    full = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"Running on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
