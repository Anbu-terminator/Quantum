# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re, logging
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

logging.basicConfig(level=logging.INFO)

# locate frontend folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

HEX_CHARS = set("0123456789abcdefABCDEF")

def only_hex(s: str) -> str:
    if not s:
        return ""
    return ''.join(ch for ch in s if ch in HEX_CHARS)

def find_iv_cipher(field: str):
    """Return (iv_hex, cipher_hex) or (None,None). Prefer first token:token but fallback to all-hex split."""
    if not field or not isinstance(field, str):
        return None, None

    s = field.replace('%3A', ':').replace('%3a', ':').strip()
    if ':' in s:
        left, right = s.split(':', 1)
        left_h = only_hex(left)
        right_h = only_hex(right)
        if len(left_h) >= 32 and len(right_h) >= 32:
            iv = left_h[:32]
            cipher = right_h
            # if cipher was prefixed with repeated IV, drop it
            while cipher.startswith(iv):
                cipher = cipher[len(iv):]
            return iv, cipher

    # fallback: take all hex and split
    allh = only_hex(s)
    if len(allh) >= 64:
        iv = allh[:32]
        cipher = allh[32:]
        while cipher.startswith(iv):
            cipher = cipher[len(iv):]
        return iv, cipher

    return None, None

def pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= AES.block_size and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b

def extract_first_token_from_bytes(pt: bytes) -> bytes:
    """Return bytes before first b'::' if present, else full pt."""
    idx = pt.find(b"::")
    if idx != -1:
        return pt[:idx].strip()
    return pt.strip()

def decode_and_clean_value(val_bytes: bytes, label: str) -> str:
    """Try utf-8 -> latin1 -> numeric extraction -> printable fallback."""
    # 1) try utf-8
    try:
        s = val_bytes.decode('utf-8')
    except Exception:
        s = val_bytes.decode('latin-1', errors='ignore')

    s = s.strip()
    # quick check: if string contains visible digits or slash (for bpm/spo2) accept
    if re.search(r'\d', s):
        # keep only reasonable chars
        candidate = re.search(r'[-+]?\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?', s)
        if candidate:
            return candidate.group(0)
        # else return cleaned alnum (short)
        short = re.sub(r'[^0-9A-Za-z.\-+/]', '', s)
        if short:
            return short

    # 2) If no digits or decoding failed, try to extract numeric from bytes directly
    m = re.search(rb'(\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?)', val_bytes)
    if m:
        try:
            return m.group(0).decode('ascii')
        except Exception:
            return m.group(0).decode('latin-1', errors='ignore')

    # 3) printable ASCII fallback
    printable = ''.join(chr(b) for b in val_bytes if 32 <= b < 127).strip()
    printable = re.sub(r'\s+', ' ', printable)
    if printable:
        # trim to 64 chars
        return printable[:64]
    return "N/A"

def find_quantum_hex_in_bytes(pt: bytes):
    m = re.search(rb'([0-9a-fA-F]{32})', pt)
    if m:
        try:
            return m.group(1).decode('ascii')
        except Exception:
            return None
    return None

def decrypt_field(field_value: str, key_hex: str, label: str):
    """
    Returns (value_string, quantum_hex_or_None, error_or_None)
    """
    try:
        iv_hex, cipher_hex = find_iv_cipher(field_value)
        if not iv_hex or not cipher_hex:
            return None, None, "iv_or_cipher_not_found"

        iv_hex = only_hex(iv_hex)[:32]
        cipher_hex = only_hex(cipher_hex)
        if len(iv_hex) != 32 or len(cipher_hex) < 32:
            return None, None, "invalid_hex_length"

        try:
            iv = unhexlify(iv_hex)
            ct = unhexlify(cipher_hex)
        except Exception as e:
            return None, None, f"hex_decode_error:{e}"

        try:
            key = unhexlify(key_hex)
        except Exception as e:
            return None, None, f"key_decode_error:{e}"

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt_unp = pkcs7_unpad(pt)

        # pick value bytes before first '::' (operate at bytes level)
        value_bytes = extract_first_token_from_bytes(pt_unp)

        # find quantum hex anywhere (32 hex)
        quantum = find_quantum_hex_in_bytes(pt_unp)

        # decode and clean the value
        value = decode_and_clean_value(value_bytes, label)

        # special-case: Quantum Key field: return quantum hex if found, else the value
        if label.lower() == "quantum key":
            return (quantum or value or "N/A"), quantum, None

        return value or "N/A", quantum, None

    except Exception as e:
        return None, None, str(e)


def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()


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
        data = fetch_thingspeak_latest()
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

        value, quantum, error = decrypt_field(raw, SERVER_AES_KEY_HEX, label)
        if error:
            logging.info(f"Decrypt error for {fkey} ({label}): {error}")
            decrypted[label] = "N/A"
            continue

        if label == "Quantum Key":
            decrypted[label] = quantum or value or "N/A"
        else:
            decrypted[label] = value

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })


# serve frontend
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full_path):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logging.info(f"Q-SENSE starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)
