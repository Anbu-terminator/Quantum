# server/server.py
import os, base64, traceback
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import requests
import quantum_key
import config
from Crypto.Cipher import AES

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
CORS(app)

# Start the quantum rotator. If preload fails, it will raise so we catch and let server run
try:
    quantum_key.start_rotator()
except Exception as e:
    print("[server] quantum_key.start_rotator() failed:", e)
    # continue so endpoints exist; /api/check_token will help diagnose

def _fetch_thingspeak_feeds(results=50):
    url = f"https://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": config.THINGSPEAK_READ_KEY, "results": results}
    r = requests.get(url, params=params, timeout=15)
    if r.status_code != 200:
        # explicit token error
        raise ValueError(f"bad_token_http_{r.status_code}")
    try:
        j = r.json()
    except Exception:
        raise ValueError("bad_token_invalid_json")
    if not isinstance(j, dict) or "feeds" not in j:
        raise ValueError("bad_token_missing_feeds")
    return j.get("feeds", []) or []

def _pkcs7_unpad(data: bytes):
    if not data:
        return b""
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("invalid padding bytes")
    return data[:-pad_len]

def try_decrypt(field1_b64, key_bytes, iv_bytes, nonce_bytes=None):
    if field1_b64 is None:
        return None
    try:
        ct = base64.b64decode(field1_b64)
    except Exception:
        return None
    try:
        if nonce_bytes:
            cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce_bytes)
            pt = cipher.decrypt(ct)
            return pt.decode("utf-8", errors="ignore")
        else:
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            pt = cipher.decrypt(ct)
            try:
                up = _pkcs7_unpad(pt)
                return up.decode("utf-8", errors="ignore")
            except Exception:
                # fallback: strip nulls
                return pt.rstrip(b"\0").decode("utf-8", errors="ignore")
    except Exception:
        return None

@app.route("/api/check_token")
def api_check_token():
    """Check whether THINGSPEAK_READ_KEY is valid (quick health endpoint)."""
    try:
        feeds = _fetch_thingspeak_feeds(results=1)
        return jsonify({"ok": True, "feeds_returned": len(feeds)})
    except ValueError as ve:
        return jsonify({"ok": False, "error": "bad_token", "detail": str(ve)}), 401
    except Exception as e:
        return jsonify({"ok": False, "error": "fetch_failed", "detail": str(e)}), 500

@app.route("/api/latest")
def api_latest():
    try:
        feeds = _fetch_thingspeak_feeds(results=50)
    except ValueError as ve:
        # clearly indicate token problem
        return jsonify({"error": "bad_token", "detail": str(ve)}), 401
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": "thingspeak_fetch_failed", "detail": str(e)}), 502

    out = []
    cur = quantum_key.get_current_key()
    cur_kid, cur_key_bytes, cur_iv = (cur or (None, None, None))

    for f in feeds:
        entry_id = f.get("entry_id")
        created_at = f.get("created_at")
        field1 = f.get("field1")
        field2 = (f.get("field2") or "").strip()
        field3 = (f.get("field3") or "").strip()  # iv_hex
        field5 = (f.get("field5") or "").strip()  # nonce_hex

        # 1) get or derive key
        ki = quantum_key.get_key_by_id(field2) if field2 else None
        if not ki and field2:
            # derive deterministically and store
            key_bytes, iv_bytes = quantum_key.derive_key_iv_from_keyid(field2)
            if field3:
                try:
                    iv_bytes = bytes.fromhex(field3)
                except Exception:
                    pass
            elif field5:
                try:
                    iv_bytes = bytes.fromhex(field5)
                except Exception:
                    pass
            quantum_key.store_key(field2, key_bytes, iv_bytes)
            ki = quantum_key.get_key_by_id(field2)

        if ki:
            key_bytes = ki["key"]
            iv_bytes = ki["iv"]
            key_used = "exact"
            qkey_hex = key_bytes.hex()
        elif cur_key_bytes:
            key_bytes = cur_key_bytes
            iv_bytes = cur_iv
            key_used = "fallback"
            qkey_hex = key_bytes.hex()
        else:
            key_bytes = None
            iv_bytes = None
            key_used = None
            qkey_hex = None

        nonce_bytes = None
        if field5:
            try:
                nonce_bytes = bytes.fromhex(field5)
            except Exception:
                nonce_bytes = None

        if key_bytes and field1:
            decrypted_text = try_decrypt(field1, key_bytes, iv_bytes, nonce_bytes=nonce_bytes)
            decrypt_error = None if decrypted_text else "decrypt_failed"
        else:
            decrypted_text = None
            decrypt_error = "no_key_available" if not key_bytes else "no_ciphertext"

        out.append({
            "entry_id": entry_id,
            "created_at": created_at,
            "field1": field1,
            "field2": field2,
            "field3": field3,
            "field5": field5,
            "key_used": key_used,
            "qkey_hex": qkey_hex,
            "decrypted_text": decrypted_text,
            "decrypt_error": decrypt_error
        })

    return jsonify(out)


@app.route("/api/quantum_key")
def api_quantum_key():
    auth = request.args.get("auth", "")
    key_id = request.args.get("key_id", "")
    if auth != config.ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    if key_id:
        ki = quantum_key.get_key_by_id(key_id)
        if not ki:
            return jsonify({"error": "no_such_key"}), 404
        return jsonify({"key_id": key_id, "key": ki["key"].hex(), "iv": ki["iv"].hex()})
    cur = quantum_key.get_current_key()
    if not cur:
        return jsonify({"error": "no_key_yet"}), 503
    kid, key_bytes, iv_bytes = cur
    return jsonify({"key_id": kid, "key": key_bytes.hex(), "iv": iv_bytes.hex()})

@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:path>")
def static_files(path):
    fp = os.path.join(FRONTEND_DIR, path)
    if os.path.exists(fp):
        return send_from_directory(FRONTEND_DIR, path)
    return send_from_directory(FRONTEND_DIR, "index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    print(f"Starting server on 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=True)
