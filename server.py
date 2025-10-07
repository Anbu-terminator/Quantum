# server.py
from flask import Flask, jsonify, send_from_directory
import requests
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii
import config
from quantum_key import get_quantum_tag
import hashlib
import hmac

app = Flask(__name__, static_folder="../frontend", static_url_path="/")

THINGSPEAK_FEEDS_URL = f"https://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?results=5"

def hex_to_bytes(h: str) -> bytes:
    return binascii.unhexlify(h)

AES_KEY = hex_to_bytes(config.SERVER_AES_KEY_HEX)

def verify_and_decrypt_field(field_value: str):
    """
    Expect field_value format: base64(iv + ciphertext) | base64(hmac_tag)
    Returns decrypted string on success, or an error message.
    """
    try:
        if "|" not in field_value:
            return {"ok": False, "error": "invalid_format"}
        part_enc, part_tag = field_value.split("|", 1)
        enc = b64decode(part_enc)
        tag = b64decode(part_tag)
        # split iv (16) + ciphertext
        iv = enc[:16]
        ciphertext = enc[16:]
        # verify quantum tag: recompute the same algorithm used on device
        # here we call get_quantum_tag to generate expected tag (it uses HMAC of ciphertext and token)
        expected_tag_b64 = get_quantum_tag(config.IBM_API_TOKEN, ciphertext, length=len(tag), use_ibm=config.USE_IBM_QUANTUM)
        expected_tag = b64decode(expected_tag_b64)
        if not hmac.compare_digest(expected_tag, tag):
            return {"ok": False, "error": "tag_mismatch"}
        # decrypt AES-128-CBC
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return {"ok": True, "value": plaintext.decode('utf-8')}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@app.route("/api/latest")
def api_latest():
    resp = requests.get(THINGSPEAK_FEEDS_URL, params={"api_key": config.THINGSPEAK_READ_KEY})
    if resp.status_code != 200:
        return jsonify({"ok": False, "error": "thingspeak_fetch_failed", "status": resp.status_code}), 500
    data = resp.json()
    feeds = data.get("feeds", [])
    if not feeds:
        return jsonify({"ok": True, "feeds": []})
    latest = feeds[-1]
    # fields 1..5
    decoded = {}
    for i in range(1,6):
        key = f"field{i}"
        raw = latest.get(key)
        if raw is None:
            decoded[key] = {"ok": False, "error": "missing_field"}
            continue
        decoded[key] = verify_and_decrypt_field(raw)
    # Also include feed created_at, entry_id
    return jsonify({"ok": True, "entry_id": latest.get("entry_id"), "created_at": latest.get("created_at"), "decoded": decoded})

# Serve frontend files
@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:p>")
def static_proxy(p):
    return send_from_directory(app.static_folder, p)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
