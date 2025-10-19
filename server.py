# server.py
from flask import Flask, jsonify, send_from_directory, request, abort
import requests, os, re
from binascii import unhexlify
from Crypto.Cipher import AES
from config import *
from quantum_key import get_quantum_challenge

# --- Locate frontend folder robustly ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))
if not os.path.exists(FRONTEND_FOLDER):
    FRONTEND_FOLDER = os.path.abspath(os.path.join(BASE_DIR, "frontend"))  # fallback

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

# ---------- Helpers ----------
def _sanitize_printable_from_bytes(b: bytes) -> str:
    # Keep only printable ASCII characters
    return ''.join(chr(c) for c in b if 32 <= c <= 126).strip()

def _first_ascii_match(b: bytes, pattern: bytes) -> str | None:
    m = re.search(pattern, b)
    if not m:
        return None
    try:
        return m.group(0).decode('ascii', errors='ignore')
    except Exception:
        return None

# --- AES decrypt + robust parsing ---
def aes_decrypt_and_parse(cipher_hex: str, key_hex: str):
    """
    Returns a dict:
    {
      "ok": bool,
      "value": <clean sensor value or 'N/A'>,
      "challenge": <challenge_id or None>,
      "quantum": <quantum_hex or None>,
      "raw": <bytes decrypted (unpadded)>,
      "error": <error message if any>
    }
    """
    out = {"ok": False, "value": None, "challenge": None, "quantum": None, "raw": None, "error": None}
    try:
        if ":" not in cipher_hex:
            out["error"] = "invalid_format"
            return out
        iv_hex, ct_hex = cipher_hex.split(":", 1)  # only split on the first colon
        # ensure even-length hex
        if len(iv_hex) % 2 != 0 or len(ct_hex) % 2 != 0:
            out["error"] = "hex_length_invalid"
            return out

        key = unhexlify(key_hex)
        iv = unhexlify(iv_hex)
        ct = unhexlify(ct_hex)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = cipher.decrypt(ct)  # bytes

        # Try PKCS7 unpad if valid
        try:
            pad_len = pt[-1]
            if 1 <= pad_len <= AES.block_size and pt[-pad_len:] == bytes([pad_len]) * pad_len:
                pt_unpadded = pt[:-pad_len]
            else:
                pt_unpadded = pt
        except Exception:
            pt_unpadded = pt

        out["raw"] = pt_unpadded

        # 1) Quick attempt: decode utf-8 and parse 'value::challenge::quantum'
        try:
            s = pt_unpadded.decode("utf-8")
            if "::" in s:
                parts = s.split("::")
                # parts[0] = value (or 'Q' for quantum key), parts[1] = challenge, parts[2] = quantum_hex
                value_part = parts[0].strip() if len(parts) > 0 else None
                challenge_part = parts[1].strip() if len(parts) > 1 else None
                quantum_part = parts[2].strip() if len(parts) > 2 else None

                # If this is the "Quantum Key" field (Arduino sends 'Q::challenge::quantum'),
                # prefer returning the quantum hex itself. Otherwise return the value_part.
                out["challenge"] = challenge_part
                out["quantum"] = quantum_part
                out["value"] = quantum_part if (value_part == "Q" and quantum_part) else (value_part or "N/A")
                out["ok"] = True
                return out
        except Exception:
            # utf-8 decode failed — continue to robust bytes parsing
            pass

        # 2) Bytes-level regex: look for pattern value::digits-digits::32hex
        m = re.search(rb'(?P<val>.*?)::(?P<chall>\d+\-\d+)::(?P<q>[0-9a-fA-F]{32})', pt_unpadded, flags=re.DOTALL)
        if m:
            val_b = m.group('val')
            challenge_b = m.group('chall')
            q_b = m.group('q')

            val_clean = _sanitize_printable_from_bytes(val_b)
            challenge = challenge_b.decode('ascii', errors='ignore')
            qhex = q_b.decode('ascii', errors='ignore')

            out["challenge"] = challenge
            out["quantum"] = qhex
            # Quantum Key field uses value 'Q' before separators; if val_clean == 'Q' return qhex
            out["value"] = qhex if val_clean == "Q" else (val_clean or "N/A")
            out["ok"] = True
            return out

        # 3) If no full pattern, try to at least extract a 32-hex quantum key anywhere
        q_any = _first_ascii_match(pt_unpadded, rb'[0-9a-fA-F]{32}')
        if q_any:
            out["quantum"] = q_any
            # try to extract an obvious numeric value (temp like 25.34 or bpm/spo2 like 72/98.5)
            # common patterns: number with optional decimal, or number/number(.)
            mval = re.search(rb'(\d{1,3}(?:\.\d+)?(?:/\d{1,3}(?:\.\d+)?)?)', pt_unpadded)
            if mval:
                try:
                    out["value"] = mval.group(1).decode('ascii', errors='ignore')
                except Exception:
                    out["value"] = _sanitize_printable_from_bytes(mval.group(1))
            else:
                # fallback: keep printable slice of entire payload (but strip the quantum tail if present)
                printable = _sanitize_printable_from_bytes(pt_unpadded)
                # if printable ends with the discovered quantum hex, remove it and trailing separators
                if printable.endswith(q_any):
                    printable = printable[: -len(q_any)].rstrip(': ')
                out["value"] = printable or "N/A"
            out["ok"] = True
            return out

        # 4) Last resort: return a sanitized printable string of everything
        printable_all = _sanitize_printable_from_bytes(pt_unpadded)
        out["value"] = printable_all or "N/A"
        out["ok"] = True
        return out

    except Exception as e:
        out["error"] = str(e)
        return out

# --- Fetch latest ThingSpeak feed ---
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# --- API: Quantum Key Generator ---
@app.route("/quantum", methods=["GET"])
def api_quantum():
    token = request.args.get("token")
    if token != ESP_AUTH_TOKEN:
        abort(401)
    n = int(request.args.get("n", 16))
    q_hex = get_quantum_challenge(n)
    return jsonify({"ok": True, "quantum_hex": q_hex})

# --- API: Decrypt latest ThingSpeak feed ---
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
    # For debugging you can collect details per field if needed:
    debug_info = {}

    for fkey, label in fields.items():
        raw = latest.get(fkey)
        if not raw:
            decrypted[label] = "N/A"
            debug_info[label] = {"note": "no field value"}
            continue

        parsed = aes_decrypt_and_parse(raw, SERVER_AES_KEY_HEX)
        debug_info[label] = parsed  # keep detailed info for debugging if necessary

        if not parsed.get("ok"):
            # If parsing failed, return a safe fallback
            decrypted[label] = "N/A"
            continue

        # For the 'Quantum Key' field we want the actual quantum hex if available,
        # otherwise fall back to the parsed value.
        if label == "Quantum Key":
            decrypted[label] = parsed.get("quantum") or parsed.get("value") or "N/A"
        else:
            # For sensor fields return the value (e.g., "25.34", "50.12", "1", "72/98.5")
            decrypted[label] = parsed.get("value") or "N/A"

    return jsonify({
        "ok": True,
        "decrypted": decrypted,
        "timestamp": latest.get("created_at"),
        # Include debug_info only if you want to inspect details; remove/comment out in production
        # "debug": debug_info
    })

# --- Serve frontend files properly ---
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path):
    full_path = os.path.join(FRONTEND_FOLDER, path)
    if not os.path.exists(full_path):
        path = "index.html"  # fallback to SPA root
    return send_from_directory(FRONTEND_FOLDER, path)

# --- Run App ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"✅ Q-SENSE running at http://127.0.0.1:{port}")
    print(f"📁 Serving frontend from: {FRONTEND_FOLDER}")
    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )
