# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re, struct
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

# --- Locate frontend folder robustly ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------- Helpers ----------
HEX_RE = re.compile(r'[0-9a-fA-F]+')

def _only_hex(s: str) -> str:
    """Return only hex characters from s."""
    return ''.join(ch for ch in s if ch in "0123456789abcdefABCDEF")

def _find_iv_and_cipher(field: str):
    """
    Robustly find IV (16 bytes -> 32 hex chars) and ciphertext hex from a field value.
    Handles strings like "iv:cipher", but also messy multi-colon cases.
    Returns (iv_hex, cipher_hex) or (None, None) on failure.
    """
    if not field or not isinstance(field, str):
        return None, None

    # Normalize whitespace and URL-encoded colon etc.
    s = field.replace('%3A', ':').replace('%3a', ':').strip()

    # Split on colons to get tokens; tokens may contain non-hex noise
    tokens = s.split(':')
    # Try to find the first token that contains at least 32 hex chars (potential IV)
    for i, tok in enumerate(tokens):
        tok_hex = _only_hex(tok)
        if len(tok_hex) >= 32:
            iv_hex = tok_hex[:32]  # take first 32 hex chars as IV
            # Build cipher hex from remainder tokens (and remainder of the tok after iv)
            remainder = tok_hex[32:]  # leftover from same token
            # concatenate remainder + all tokens after i
            tail = remainder + ''.join(_only_hex(t) for t in tokens[i+1:])
            # Remove any accidental repeated iv at tail (common in collected samples)
            # If tail starts with iv_hex again, strip it
            if tail.startswith(iv_hex):
                tail = tail[len(iv_hex):]
            if len(tail) == 0:
                # no ciphertext (invalid)
                return None, None
            return iv_hex, tail

    # Fallback: try to match a contiguous hex pair "32hex" followed by a multi-of-32 hex ciphertext
    allhex = _only_hex(s)
    # if allhex contains at least 32+32 hex chars, take first 32 as iv, rest as cipher
    if len(allhex) >= 64:
        iv_hex = allhex[:32]
        cipher_hex = allhex[32:]
        return iv_hex, cipher_hex

    return None, None

def _pkcs7_unpad(b: bytes) -> bytes | None:
    if not b:
        return None
    pad_len = b[-1]
    if pad_len < 1 or pad_len > AES.block_size:
        # invalid padding -> return original (we'll still attempt parsing)
        return b
    if b[-pad_len:] != bytes([pad_len]) * pad_len:
        return b
    return b[:-pad_len]

def _extract_value_from_plaintext(pt: bytes):
    """
    Decodes plaintext bytes to a value string.
    Expected Arduino plaintext: "<value>::<challenge>::<quantum_hex>"
    We will:
     - try utf-8 decode and split on "::"
     - if not ascii/utf-8, fallback to printable extraction and numeric heuristics
    """
    # 1) Try utf-8 decode cleanly
    try:
        s = pt.decode('utf-8')
    except Exception:
        # fallback latin-1 decode
        s = pt.decode('latin-1', errors='ignore')

    # If contains separators, parse forward
    if "::" in s:
        parts = s.split("::")
        val = parts[0].strip()
        # quantum if present
        quantum = parts[2].strip() if len(parts) > 2 else None
        # If Arduino used 'Q' for quantum field, user wants quantum hex returned
        if val == "Q" and quantum and re.fullmatch(r'[0-9a-fA-F]{32}', quantum):
            return quantum
        # otherwise return the plain value (cleaned)
        return _clean_sensor_value(val)

    # No separators — try to extract a 32-hex quantum anywhere
    m = re.search(r'([0-9a-fA-F]{32})', s)
    if m:
        q = m.group(1)
        # strip the quantum from the text and try to find a numeric before it
        before = s.split(q)[0]
        num = _find_best_number(before)
        return num or q

    # No quantum found — try numeric extraction
    num = _find_best_number(s)
    if num:
        return num

    # final fallback: printable ASCII trimmed
    printable = ''.join(ch for ch in s if 32 <= ord(ch) <= 126).strip()
    return printable or "N/A"

def _clean_sensor_value(s: str) -> str:
    """Remove stray characters but keep digits, dot, slash, minus, plus."""
    cleaned = re.sub(r'[^0-9\.\-+/]', '', s).strip()
    return cleaned or "N/A"

def _find_best_number(s: str) -> str | None:
    """
    Try patterns in order:
      - number with optional decimal
      - number/number (e.g., bpm/spo2)
      - integer
    """
    s2 = ''.join(ch for ch in s if 32 <= ord(ch) <= 126)
    # bpm/spo2 like 72/98.5
    m = re.search(r'\d{1,3}/\d{1,3}(?:\.\d+)?', s2)
    if m:
        return m.group(0)
    # decimal or integer
    m = re.search(r'[-+]?\d{1,4}(?:\.\d+)?', s2)
    if m:
        return m.group(0)
    return None

# ---------- AES decrypt and parse ----------
def aes_decrypt_and_parse(field_value: str, key_hex: str, label: str):
    """
    Returns dict: {ok, value, quantum, error}
    """
    out = {"ok": False, "value": "N/A", "quantum": None, "error": None}
    try:
        iv_hex, cipher_hex = _find_iv_and_cipher(field_value)
        if not iv_hex or not cipher_hex:
            out["error"] = "iv_or_cipher_not_found"
            return out

        # ensure even-length hex strings consisting only of hex chars
        iv_hex = _only_hex(iv_hex)
        cipher_hex = _only_hex(cipher_hex)
        if len(iv_hex) < 32:
            out["error"] = "iv_too_short"
            return out

        # trim IV to 32 chars (16 bytes)
        iv_hex = iv_hex[:32]

        try:
            iv = unhexlify(iv_hex)
            ct = unhexlify(cipher_hex)
        except Exception as e:
            out["error"] = f"hex_unhexlify_error:{e}"
            return out

        key = unhexlify(key_hex)

        # AES-CBC decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)

        # Try PKCS7 unpad — Arduino pads manually so this should succeed
        pt_unpadded = _pkcs7_unpad(pt) or pt

        # Extract quantum if present (32 hex) from decoded text
        decoded_try = None
        try:
            decoded_try = pt_unpadded.decode('utf-8')
        except Exception:
            decoded_try = pt_unpadded.decode('latin-1', errors='ignore')

        m_q = re.search(r'([0-9a-fA-F]{32})', decoded_try)
        if m_q:
            out["quantum"] = m_q.group(1)

        # Extract the value according to Arduino format
        value = _extract_value_from_plaintext(pt_unpadded)
        out["value"] = value
        out["ok"] = True
        return out

    except Exception as e:
        out["error"] = str(e)
        return out

# ---------- ThingSpeak fetch ----------
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# ---------- Routes ----------
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

        parsed = aes_decrypt_and_parse(raw, SERVER_AES_KEY_HEX, label)
        if not parsed["ok"]:
            decrypted[label] = f"error:{parsed['error']}"
            continue

        # For Quantum Key field prefer the found quantum hex
        if label == "Quantum Key":
            decrypted[label] = parsed.get("quantum") or parsed.get("value")
        else:
            decrypted[label] = parsed.get("value")

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at")
    })

# --- Serve frontend files ---
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full_path):
        path = "index.html"
    return send_from_directory(FRONTEND_FOLDER, path)

# --- Run App ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"✅ Q-SENSE running at http://127.0.0.1:{port}")
    print(f"📁 Serving frontend from: {FRONTEND_FOLDER}")
    app.run(host="0.0.0.0", port=port, debug=True)
