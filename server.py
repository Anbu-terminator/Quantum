# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re, struct, logging
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

# --- Basic app / frontend locate ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")
logging.basicConfig(level=logging.INFO)

# ---------- Helpers ----------
HEX_CHARS = set("0123456789abcdefABCDEF")

def _only_hex(s: str) -> str:
    return ''.join(ch for ch in (s or "") if ch in HEX_CHARS)

def _find_iv_and_cipher(field: str):
    """
    Robustly locate a 16-byte IV (32 hex chars) and ciphertext hex in a ThingSpeak field value.
    Many samples contained the iv, then the ciphertext and sometimes the iv repeated.
    We return (iv_hex, cipher_hex) using defensive extraction.
    """
    if not field or not isinstance(field, str):
        return None, None

    s = field.replace('%3A', ':').strip()
    tokens = s.split(':')

    # Search tokens for something containing >= 32 hex chars (candidate IV)
    for i, tok in enumerate(tokens):
        rawhex = _only_hex(tok)
        if len(rawhex) >= 32:
            iv_hex = rawhex[:32]
            remainder = rawhex[32:]
            # join the remainder of this token with the remainder tokens (hex-only)
            tail = remainder + ''.join(_only_hex(t) for t in tokens[i+1:])
            # Some samples have the IV appended at the end of tail; keep the tail as-is
            # (we used to strip a trailing IV, but that produced invalid block sizes).
            # If there is an accidental duplication at the very start of the tail, strip it:
            while tail.startswith(iv_hex):
                tail = tail[len(iv_hex):]
            # If the tail is empty, try to fallback to full-hex approach below
            if tail:
                return iv_hex, tail

    # Fallback: extract all hex present and split into iv(32) + cipher(remaining)
    allhex = _only_hex(s)
    if len(allhex) >= 64:
        iv_hex = allhex[:32]
        cipher_hex = allhex[32:]
        return iv_hex, cipher_hex

    return None, None

def _pkcs7_unpad(b: bytes) -> bytes:
    if not b:
        return b
    pad_len = b[-1]
    if 1 <= pad_len <= AES.block_size and b[-pad_len:] == bytes([pad_len]) * pad_len:
        return b[:-pad_len]
    # invalid padding -> return original (we'll still attempt parsing)
    return b

# Heuristics / plausibility
def _plausible_for_label(value_float: float, label: str) -> bool:
    label_low = label.lower()
    if "temp" in label_low:
        return -10.0 <= value_float <= 80.0
    if "humid" in label_low:
        return 0.0 <= value_float <= 100.0
    if "ir" in label_low:
        return int(round(value_float)) in (0, 1)
    if "max30100" in label_low:
        return 20.0 <= value_float <= 220.0
    return True

# Try to extract numeric / printable from plaintext bytes
def _extract_value_from_plaintext_bytes(pt_bytes: bytes, label: str):
    """
    Multiple layered attempts:
      1) decode latin-1 and search for 'value::challenge::quantumhex' pattern;
      2) if present, take token before the challenge as the value (clean it);
      3) otherwise scan printable substrings; prefer decimals in realistic ranges;
      4) attempt binary float/int scans as a last resort;
      5) fallback to cleaned printable tail.
    """
    s = pt_bytes.decode("latin-1", errors="ignore")

    # 1) look for a 32-hex quantum anywhere
    for m in re.finditer(r'([0-9a-fA-F]{32})', s):
        q = m.group(1)
        left = s[: m.start() ]
        # split by '::' tokens to find the "value" token before the challenge token
        parts = left.split("::")
        if len(parts) >= 2:
            candidate_raw = parts[-1]  # text between last '::' and quantum -> this is *challenge*
            # value token is the token before the challenge token:
            value_token = parts[-2].strip()
            # clean common noise and keep digits, decimal point, slash (for bpm/spo2), +/- and alnum
            cleaned = re.sub(r'[^0-9A-Za-z\.\-+/]', '', value_token)
            # if it's clearly numeric (including x/y), prefer that
            mnum = re.search(r'\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?', cleaned)
            if mnum:
                v = mnum.group(0)
                # validate plausibility if numeric
                try:
                    if "/" in v:
                        leftpart = float(v.split("/")[0])
                        if _plausible_for_label(leftpart, label):
                            return v
                    else:
                        if _plausible_for_label(float(v), label):
                            return v
                except Exception:
                    pass
            # if cleaned not numeric, return short alnum tail
            tail_alnum = re.search(r'([A-Za-z0-9.\-+/]{1,64})$', cleaned)
            if tail_alnum:
                return tail_alnum.group(1)

        # if pattern present but unable to parse via tokens, try immediate numeric before quantum
        left_nums = re.findall(r'\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?', left)
        if left_nums:
            for cand in reversed(left_nums):
                try:
                    if "/" in cand:
                        base = float(cand.split("/")[0])
                    else:
                        base = float(cand)
                    if _plausible_for_label(base, label):
                        return cand
                except Exception:
                    continue

    # 2) No 32-hex quantum pattern -> parse general '::' pattern in s
    if "::" in s:
        parts = s.split("::")
        if len(parts) >= 2:
            # take first token as likely value (Arduino constructs value::challenge::quantum)
            candidate = parts[0].strip()
            cleaned = re.sub(r'[^0-9A-Za-z\.\-+/]', '', candidate)
            mnum = re.search(r'\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?', cleaned)
            if mnum:
                cand = mnum.group(0)
                try:
                    if _plausible_for_label(float(cand.split("/")[0]) if "/" in cand else float(cand), label):
                        return cand
                except Exception:
                    pass
            tail_alnum = re.search(r'([A-Za-z0-9.\-+/]{1,64})$', cleaned)
            if tail_alnum:
                return tail_alnum.group(1)

    # 3) scan printable substrings and rank candidates by plausibility
    printable_pieces = re.findall(r'[\x20-\x7E]{1,80}', s)
    best_score = -999
    best_val = None
    for piece in printable_pieces:
        # prefer x/y patterns first (MAX30100)
        mxy = re.search(r'\d{1,3}/\d{1,3}(?:\.\d+)?', piece)
        if mxy:
            cand = mxy.group(0)
            try:
                base = float(cand.split('/')[0])
                score = 50 if _plausible_for_label(base, label) else 0
                if score > best_score:
                    best_score = score; best_val = cand
            except Exception:
                pass
        # numeric candidate
        mnum = re.search(r'\d{1,3}(?:\.\d+)?', piece)
        if mnum:
            cand = mnum.group(0)
            try:
                base = float(cand)
                score = 30 if _plausible_for_label(base, label) else 5
                # longer printable piece with digits is slightly more trustworthy
                score += max(0, min(10, len(piece)//5))
                if score > best_score:
                    best_score = score; best_val = cand
            except Exception:
                pass
        # alphanumeric fallback
        al = re.search(r'([A-Za-z0-9.\-+/]{1,64})', piece)
        if al and best_score < 5:
            best_score = 1
            best_val = al.group(1)

    if best_val is not None:
        return best_val

    # 4) try binary scans: floats (4 bytes LE) then uint16
    for i in range(0, len(pt_bytes) - 3):
        chunk = pt_bytes[i:i+4]
        try:
            f = struct.unpack('<f', chunk)[0]
            if _plausible_for_label(f, label):
                # format nicely
                return f"{f:.2f}"
        except Exception:
            pass
    for i in range(0, len(pt_bytes) - 1):
        chunk = pt_bytes[i:i+2]
        try:
            u = struct.unpack('<H', chunk)[0]
            if _plausible_for_label(float(u), label):
                return str(u)
        except Exception:
            pass

    # 5) final fallback - printable tail or hex fallback
    printable = ''.join(ch for ch in s if 32 <= ord(ch) <= 126).strip()
    if printable:
        # trim to a reasonable size
        p = printable[-64:]
        return p
    return "N/A"

# ---------- AES decrypt + parse ----------
def aes_decrypt_and_parse(field_value: str, key_hex: str, label: str):
    """
    Return dict: { ok: bool, value: str, quantum: str|None, error: str|None }
    """
    out = {"ok": False, "value": "N/A", "quantum": None, "error": None}
    try:
        iv_hex, cipher_hex = _find_iv_and_cipher(field_value)
        if not iv_hex or not cipher_hex:
            out["error"] = "iv_or_cipher_not_found"
            return out

        # clean hex strings (safety)
        iv_hex = _only_hex(iv_hex)[:32]
        cipher_hex = _only_hex(cipher_hex)
        if len(iv_hex) != 32 or len(cipher_hex) < 32:
            out["error"] = "invalid_iv_or_cipher_length"
            return out

        try:
            iv = unhexlify(iv_hex)
            ct = unhexlify(cipher_hex)
        except Exception as e:
            out["error"] = f"hex_decode_error:{e}"
            return out

        key = unhexlify(key_hex)

        # AES-CBC decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)

        # Attempt PKCS#7 unpad; if invalid padding we still keep pt (the function returns original)
        pt_unp = _pkcs7_unpad(pt)

        # Try to decode (we use latin-1 to preserve bytes for heuristic parsing)
        decoded_try = None
        try:
            decoded_try = pt_unp.decode('utf-8', errors='ignore')
        except Exception:
            decoded_try = pt_unp.decode('latin-1', errors='ignore')

        # Look for 32-hex quantum
        m_q = re.search(r'([0-9a-fA-F]{32})', decoded_try)
        if m_q:
            out["quantum"] = m_q.group(1)

        # Extract the sensor value using layered heuristics
        value = _extract_value_from_plaintext_bytes(pt_unp, label)
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
