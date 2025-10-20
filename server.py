# server.py
import os
import re
import logging
from binascii import unhexlify, hexlify
from flask import Flask, jsonify, send_from_directory, request, abort
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from config import *               # must provide SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN, THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY
from quantum_key import get_quantum_challenge

logging.basicConfig(level=logging.INFO)
DEBUG = False  # set True to log decrypted plaintext bytes for troubleshooting

# locate frontend
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

HEX_CHARS = set("0123456789abcdefABCDEF")
NUM_PATTERN = re.compile(r'[-+]?\d{1,4}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?')

def only_hex(s: str) -> str:
    return ''.join(ch for ch in (s or "") if ch in HEX_CHARS)

def find_iv_and_cipher(field: str):
    """
    Robustly find IV (32 hex chars) and ciphertext hex in the field string.
    - Handles 'iv:cipher' clean case.
    - Handles 'iv:cipher...iv' repeated IV at end.
    - Falls back to extracting all hex, splitting first 32 chars as IV.
    Returns (iv_hex, cipher_hex) or (None, None).
    """
    if not field or not isinstance(field, str):
        return None, None

    s = field.replace('%3A', ':').replace('%3a', ':').strip()

    # Clean-case: first colon separates iv and cipher
    if ':' in s:
        left, right = s.split(':', 1)
        left_h = only_hex(left)
        right_h = only_hex(right)
        if len(left_h) >= 32 and len(right_h) >= 32:
            iv = left_h[:32]
            cipher = right_h
            # Remove trailing repeated iv occurrences
            while cipher.endswith(iv):
                cipher = cipher[:-len(iv)]
            # Truncate cipher to a multiple of 32 hex chars (16-byte blocks)
            if len(cipher) >= 32 and len(cipher) % 32 != 0:
                L = (len(cipher) // 32) * 32
                cipher = cipher[:L]
            if len(cipher) >= 32:
                return iv, cipher

    # Fallback: take all hex characters and split first 32 as IV
    allh = only_hex(s)
    if len(allh) >= 64:
        iv = allh[:32]
        cipher = allh[32:]
        while cipher.endswith(iv):
            cipher = cipher[:-len(iv)]
        if len(cipher) >= 32 and len(cipher) % 32 != 0:
            L = (len(cipher) // 32) * 32
            cipher = cipher[:L]
        if len(cipher) >= 32:
            return iv, cipher

    return None, None

def safe_unpad(pt: bytes) -> bytes:
    """Try Crypto unpad first; fallback to manual check; otherwise return original bytes."""
    try:
        return unpad(pt, AES.block_size)
    except Exception:
        if not pt:
            return pt
        pad_len = pt[-1]
        if 1 <= pad_len <= AES.block_size and pt[-pad_len:] == bytes([pad_len]) * pad_len:
            return pt[:-pad_len]
        return pt

def bytes_to_printable(b: bytes) -> str:
    return ''.join(chr(x) for x in b if 32 <= x <= 126)

def parse_plaintext_bytes(pt_bytes: bytes, label: str):
    """
    Parse the plaintext bytes into (value, quantum).
    Expected plaintext: "<value>::<challenge_id>::<quantum_hex>"
    Strategy:
      - prefer splitting on b'::' (bytes)
      - if not found, find 32-hex quantum and numeric before it
      - else search numeric anywhere
      - fallback to printable ascii substring
    """
    quantum = None
    m_q = re.search(rb'([0-9a-fA-F]{32})', pt_bytes)
    if m_q:
        quantum = m_q.group(1).decode('ascii')

    # Split by bytes-level :: if present
    if b"::" in pt_bytes:
        parts = pt_bytes.split(b"::")
        # first token is value
        raw_val = parts[0].strip()
        # decode safely
        try:
            s = raw_val.decode('utf-8').strip()
        except Exception:
            s = raw_val.decode('latin-1', errors='ignore').strip()
        # extract numeric or formatted value
        mnum = NUM_PATTERN.search(s)
        if mnum:
            value = mnum.group(0)
            return value, quantum
        # fallback cleaned alnum
        cleaned = re.sub(r'[^0-9A-Za-z./\-+]', '', s)
        if cleaned:
            return cleaned, quantum
        # if nothing, continue to other heuristics

    # If quantum present, try numeric before quantum
    if m_q:
        qstart = m_q.start()
        before = pt_bytes[:qstart]
        # search numeric from end
        m_rev = re.search(rb'(\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?)', before[::-1])
        if m_rev:
            cand = m_rev.group(0)[::-1]
            try:
                return cand.decode('ascii'), quantum
            except Exception:
                return cand.decode('latin-1', errors='ignore'), quantum

    # search numeric anywhere
    try:
        candidate_text = pt_bytes.decode('latin-1', errors='ignore')
    except Exception:
        candidate_text = bytes_to_printable(pt_bytes)
    m_any = NUM_PATTERN.search(candidate_text)
    if m_any:
        return m_any.group(0), quantum

    # final printable fallback
    printable = bytes_to_printable(pt_bytes).strip()
    if printable:
        toks = re.findall(r'[0-9A-Za-z./\-+]{1,64}', printable)
        if toks:
            return toks[-1], quantum
        return printable, quantum

    return "N/A", quantum

def decrypt_field(field_value: str, key_hex: str, label: str):
    """
    Returns (value_str, quantum_or_None, error_or_None)
    """
    try:
        iv_hex, cipher_hex = find_iv_and_cipher(field_value)
        if not iv_hex or not cipher_hex:
            return None, None, "iv_or_cipher_not_found"

        try:
            iv = unhexlify(iv_hex)
            ct = unhexlify(cipher_hex)
        except Exception as e:
            return None, None, f"hex_decode_error:{e}"

        key = unhexlify(key_hex)

        if len(ct) == 0:
            return None, None, "cipher_empty"

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt_unp = safe_unpad(pt)

        if DEBUG:
            logging.info("FIELD (%s) decrypted raw bytes: %s", label, hexlify(pt_unp)[:200])

        value, quantum = parse_plaintext_bytes(pt_unp, label)

        # Special-case quantum field: prefer quantum hex
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
            logging.info("Decrypt error for %s (%s): %s", fkey, label, error)
            decrypted[label] = "N/A"
            continue

        # For quantum field prefer the hex
        if label == "Quantum Key":
            decrypted[label] = quantum or value or "N/A"
        else:
            decrypted[label] = value

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })

@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full_path):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    logging.info(f"Q-SENSE server starting on port {port}")
    app.run(host="0.0.0.0", port=port, debug=True)
