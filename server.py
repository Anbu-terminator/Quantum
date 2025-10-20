# server.py
import os
import re
import logging
from binascii import unhexlify
from flask import Flask, jsonify, send_from_directory, request, abort
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from config import *          # expects SERVER_AES_KEY_HEX, ESP_AUTH_TOKEN, THINGSPEAK_CHANNEL_ID, THINGSPEAK_READ_KEY
from quantum_key import get_quantum_challenge

logging.basicConfig(level=logging.INFO)
DEBUG = False   # set True to see decrypted raw plaintexts in logs

# locate frontend folder
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = BASE_DIR

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

HEX_CHARS = set("0123456789abcdefABCDEF")

def only_hex(s: str) -> str:
    return ''.join(ch for ch in (s or "") if ch in HEX_CHARS)

def find_iv_and_cipher(field: str):
    """
    Robustly find IV (32 hex chars) and ciphertext hex in a field string.
    Returns (iv_hex, cipher_hex) or (None, None).
    """
    if not field or not isinstance(field, str):
        return None, None

    # normalize common URL-encoded colon
    s = field.replace('%3A', ':').replace('%3a', ':').strip()

    # try pattern '32hex : >=32hex' possibly with noise around
    for m in re.finditer(r'([0-9A-Fa-f]{32})[:%3A]*([0-9A-Fa-f]{32,})', s):
        iv_hex = m.group(1)
        cipher_hex = m.group(2)
        # prefer the longest contiguous hex after iv in the original substring (we already have it)
        # remove accidental repeated iv prefix in cipher (seen in feeds)
        while cipher_hex.startswith(iv_hex):
            cipher_hex = cipher_hex[len(iv_hex):]
        # choose longest prefix of cipher_hex whose length is multiple of 32 (AES blocks in hex)
        if len(cipher_hex) < 32:
            continue
        # find longest prefix length >=32 that's divisible by 32
        for L in range(len(cipher_hex), 31, -1):
            if L % 32 == 0:
                candidate = cipher_hex[:L]
                # sanity: candidate length at least 32
                if len(candidate) >= 32:
                    return iv_hex[:32], candidate
    # fallback: take all hex from string and split 32/remaining
    allh = only_hex(s)
    if len(allh) >= 64:
        iv_hex = allh[:32]
        cipher_hex = allh[32:]
        # strip repeated iv prefix in cipher
        while cipher_hex.startswith(iv_hex):
            cipher_hex = cipher_hex[len(iv_hex):]
        # truncate to multiple of 32 if necessary (take longest prefix)
        if len(cipher_hex) >= 32:
            L = (len(cipher_hex) // 32) * 32
            cipher_hex = cipher_hex[:L]
            return iv_hex[:32], cipher_hex
    return None, None

def safe_unpad(pt: bytes) -> bytes:
    """
    Try Crypto.Util.Padding.unpad; if fails, do a manual best-effort PKCS7 unpad.
    """
    try:
        return unpad(pt, AES.block_size)
    except Exception:
        # manual check
        if not pt:
            return pt
        pad_len = pt[-1]
        if 1 <= pad_len <= AES.block_size and pt[-pad_len:] == bytes([pad_len]) * pad_len:
            return pt[:-pad_len]
        # if padding invalid, return pt as-is (we'll still try to parse printable content)
        return pt

def bytes_to_printable_ascii(b: bytes) -> str:
    return ''.join(chr(x) for x in b if 32 <= x <= 126)

NUM_PATTERN = re.compile(r'[-+]?\d{1,4}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?')

def pick_best_value_from_plaintext(pt_bytes: bytes, label: str):
    """
    Return (value_str, quantum_hex_or_None).
    Steps:
     - look for b'::' delimiter bytes and take first token if printable
     - else search for a 32-hex quantum and numeric before it
     - else search numeric pattern anywhere
     - else return printable ascii segment
    """
    # find 32-hex quantum anywhere
    m_q = re.search(rb'([0-9a-fA-F]{32})', pt_bytes)
    quantum = m_q.group(1).decode('ascii') if m_q else None

    # if b'::' present, split at first occurrence and take bytes before it
    if b"::" in pt_bytes:
        first = pt_bytes.split(b"::", 1)[0].strip()
        # decode first token using utf-8, fallback latin-1
        try:
            s = first.decode('utf-8').strip()
        except Exception:
            s = first.decode('latin-1', errors='ignore').strip()
        # if looks numeric-like, return numeric token
        mnum = NUM_PATTERN.search(s)
        if mnum:
            return mnum.group(0), quantum
        # else if it's readable alpha-numeric return cleaned
        cleaned = re.sub(r'[^0-9A-Za-z./\-+]', '', s)
        if cleaned:
            return cleaned, quantum

    # try numeric directly before quantum in bytes
    if m_q:
        qstart = m_q.start()
        before = pt_bytes[:qstart]
        # search backwards for numeric pattern
        # reverse bytes to search conveniently for last numeric group
        rev = before[::-1]
        m_rev = re.search(rb'(\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?)', rev)
        if m_rev:
            cand = m_rev.group(0)[::-1]
            try:
                return cand.decode('ascii'), quantum
            except Exception:
                return cand.decode('latin-1', errors='ignore'), quantum

    # search for numeric anywhere
    m_any = NUM_PATTERN.search(pt_bytes.decode('latin-1', errors='ignore'))
    if m_any:
        return m_any.group(0), quantum

    # fallback: printable ascii substring (trim)
    printable = bytes_to_printable_ascii(pt_bytes).strip()
    if printable:
        # try last token in printable
        toks = re.findall(r'[0-9A-Za-z./\-+]{1,64}', printable)
        if toks:
            return toks[-1], quantum
        return printable, quantum

    return "N/A", quantum

def decrypt_field(raw_field: str):
    """
    Returns (value_str, quantum_hex_or_None, error_or_None)
    """
    try:
        iv_hex, cipher_hex = find_iv_and_cipher(raw_field)
        if not iv_hex or not cipher_hex:
            return None, None, "iv_or_cipher_not_found"

        # decode hex
        try:
            iv = unhexlify(iv_hex)
            ct = unhexlify(cipher_hex)
        except Exception as e:
            return None, None, f"hex_decode_error:{e}"

        key = unhexlify(SERVER_AES_KEY_HEX)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)
        pt_unp = safe_unpad(pt)

        if DEBUG:
            logging.info("raw_field (trimmed): %s", (raw_field[:200] + '...') if len(raw_field) > 200 else raw_field)
            logging.info("plaintext (bytes): %s", pt_unp[:200])

        # choose best value
        value, quantum = pick_best_value_from_plaintext(pt_unp, label="")
        return value, quantum, None
    except Exception as e:
        return None, None, str(e)

# --- ThingSpeak fetch ---
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# --- Routes ---
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

        value, quantum, error = decrypt_field(raw)
        if error:
            logging.info(f"Decrypt error for {fkey}/{label}: {error}")
            decrypted[label] = "N/A"
            continue

        # if Quantum Key field, prefer the found quantum hex
        if label == "Quantum Key":
            decrypted[label] = quantum or value or "N/A"
        else:
            decrypted[label] = value or "N/A"

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })

# serve frontend static files
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
