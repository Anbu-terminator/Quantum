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

def _only_hex(s: str) -> str:
    if not s:
        return ""
    return ''.join(ch for ch in s if ch in HEX_CHARS)

def _safe_split_iv_cipher(field: str):
    """
    Given a ThingSpeak field value, robustly find iv_hex (32 hex chars) and ciphertext hex.
    Accepts clean 'iv:cipher' and some messy variants observed in feeds.
    Returns (iv_hex, cipher_hex) or (None, None) if not found.
    """
    if not field or not isinstance(field, str):
        return None, None

    # normalize common URL-encoding of colon
    s = field.replace('%3A', ':').replace('%3a', ':').strip()

    # common clean case: first ':' separates IV and cipher
    if ':' in s:
        left, right = s.split(':', 1)
        left_hex = _only_hex(left)
        right_hex = _only_hex(right)
        if len(left_hex) >= 32 and len(right_hex) >= 32:
            iv_hex = left_hex[:32]
            cipher_hex = right_hex
            # remove accidental repeated iv at start of cipher_hex if present
            while cipher_hex.startswith(iv_hex):
                cipher_hex = cipher_hex[len(iv_hex):]
            return iv_hex, cipher_hex

    # fallback: extract all hex and split first 32 chars for IV, rest for cipher
    allhex = _only_hex(s)
    if len(allhex) >= 64:
        iv_hex = allhex[:32]
        cipher_hex = allhex[32:]
        # if cipher_hex begins with iv_hex, drop that repetition
        while cipher_hex.startswith(iv_hex):
            cipher_hex = cipher_hex[len(iv_hex):]
        return iv_hex, cipher_hex

    return None, None

def _pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad = b[-1]
    if 1 <= pad <= AES.block_size and b[-pad:] == bytes([pad]) * pad:
        return b[:-pad]
    return b

def _find_32hex_in_bytes(b: bytes):
    m = re.search(rb'([0-9a-fA-F]{32})', b)
    return m.group(1).decode('ascii') if m else None

def _extract_value_bytes(pt_unp: bytes, label: str) -> str:
    """
    Parse plaintext bytes and return the sensor value string.
    Strategy:
      1) If b"::" present, take bytes before first b"::" as value.
      2) Else if 32-hex quantum present, find a numeric/value immediately before it.
      3) Else attempt numeric regex over entire plaintext.
      4) Fallback: return printable ASCII chunk.
    """
    # 1) split by b'::'
    if b"::" in pt_unp:
        parts = pt_unp.split(b"::")
        if len(parts) >= 1:
            value_bytes = parts[0].strip()
            # decode to ascii ignoring invalid bytes
            try:
                value = value_bytes.decode('utf-8', errors='ignore').strip()
            except Exception:
                value = ''.join(chr(c) for c in value_bytes if 32 <= c < 127).strip()
            if value != "":
                return value

    # 2) search for quantum and numeric before it
    m_q = re.search(rb'([0-9a-fA-F]{32})', pt_unp)
    if m_q:
        q_start = m_q.start()
        before = pt_unp[:q_start]
        # look for the last numeric-ish token before quantum (e.g., "25.3" or "72/98.5")
        m_num = re.search(rb'(\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?)\b', before[::-1])
        if m_num:
            # m_num is on reversed bytes; reverse back
            rev = m_num.group(0)[::-1]
            try:
                val = rev.decode('ascii', errors='ignore')
                return val
            except Exception:
                try:
                    return rev.decode('latin-1').strip()
                except Exception:
                    pass
        # else fall back to any printable substring before quantum
        printable = ''.join(chr(c) for c in before if 32 <= c < 127).strip()
        if printable:
            # try to pull last token
            toks = re.findall(r'([0-9A-Za-z.\-+/]{1,64})', printable)
            if toks:
                return toks[-1]

    # 3) numeric regex on whole plaintext
    m_allnum = re.search(rb'(\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?)', pt_unp)
    if m_allnum:
        try:
            return m_allnum.group(0).decode('ascii')
        except Exception:
            return m_allnum.group(0).decode('latin-1', errors='ignore')

    # 4) final printable fallback
    printable_all = ''.join(chr(c) for c in pt_unp if 32 <= c < 127).strip()
    return printable_all or "N/A"

def decrypt_and_parse_field(field_value: str, key_hex: str, label: str):
    """
    Returns (value_str, quantum_hex_or_None, error_or_None)
    """
    try:
        iv_hex, cipher_hex = _safe_split_iv_cipher(field_value)
        if not iv_hex or not cipher_hex:
            return None, None, "iv_or_cipher_not_found"

        iv_hex = _only_hex(iv_hex)[:32]
        cipher_hex = _only_hex(cipher_hex)
        if len(iv_hex) != 32 or len(cipher_hex) < 32:
            return None, None, "invalid_hex_lengths"

        try:
            iv = unhexlify(iv_hex)
            ct = unhexlify(cipher_hex)
        except Exception as e:
            return None, None, f"hex_decode_error:{e}"

        try:
            key = unhexlify(key_hex)
        except Exception as e:
            return None, None, f"key_hex_error:{e}"

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt_unp = _pkcs7_unpad(pt)

        # find quantum 32hex in plaintext bytes
        quantum = _find_32hex_in_bytes(pt_unp)

        # value extraction from bytes
        value = _extract_value_bytes(pt_unp, label)

        # Special-case: if this is the Quantum Key field (Arduino encrypts "Q::challenge::quantum")
        if label.lower() == "quantum key":
            # prefer the discovered quantum; else, if value is "Q" return quantum if present
            if quantum:
                return quantum, quantum, None
            if value and value.upper() == "Q" and quantum:
                return quantum, quantum, None
            # fallback to value
            return value or "N/A", quantum, None

        return value or "N/A", quantum, None

    except Exception as e:
        return None, None, str(e)


# ThingSpeak fetch
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

        value, quantum, error = decrypt_and_parse_field(raw, SERVER_AES_KEY_HEX, label)
        if error:
            logging.info(f"decrypt error for {fkey}/{label}: {error}")
            decrypted[label] = "N/A"
            continue

        # For Quantum Key field prefer the quantum hex itself
        if label == "Quantum Key":
            decrypted[label] = quantum or value or "N/A"
        else:
            decrypted[label] = value or "N/A"

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
