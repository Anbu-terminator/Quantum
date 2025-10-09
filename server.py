from flask import Flask, jsonify, send_from_directory, request, abort
import requests, base64, json, uuid, os
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, SHA256
from config import *
from quantum_key import get_quantum_challenge

# --- Config ---
FRONTEND_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../frontend")
app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")
challenges = {}

# --- AES decrypt ---
def aes_decrypt_base64(cipher_b64: str, key_hex: str, iv_hex: str) -> str:
    try:
        data = base64.urlsafe_b64decode(cipher_b64 + "==")
        key = unhexlify(key_hex)
        iv = unhexlify(iv_hex)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(data), AES.block_size)
        return pt.decode("utf-8")
    except Exception as e:
        return f"error:{e}"

# --- Verify HMAC ---
def verify_hmac(hmac_b64: str, message: str, key: str) -> bool:
    try:
        expected = HMAC.new(key.encode("utf-8"), digestmod=SHA256)
        expected.update(message.encode("utf-8"))
        exp_b = base64.urlsafe_b64encode(expected.digest()).decode("utf-8").rstrip("=")
        return hmac_b64 == exp_b
    except:
        return False

# --- ThingSpeak fetch ---
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": THINGSPEAK_RESULTS}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# --- API: Quantum Challenge ---
@app.route("/quantum/challenge", methods=["GET"])
def challenge():
    cid = str(uuid.uuid4())
    token = get_quantum_challenge()
    challenges[cid] = {"token": token}
    return jsonify({"ok": True, "challenge_id": cid, "challenge_token": token})

# --- API: Decrypt latest feed ---
@app.route("/api/latest", methods=["GET"])
def api_latest():
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)
    data = fetch_thingspeak_latest()
    feeds = data.get("feeds", [])
    if not feeds:
        return jsonify({"error": "no feeds"}), 404
    feed = feeds[-1]

    fields = {'field1': 'Label1', 'field2': 'Temperature', 'field3': 'Humidity', 'field4': 'IR', 'field5': 'Label2'}
    decrypted = {}

    for fkey, fname in fields.items():
        raw = feed.get(fkey)
        if not raw: 
            decrypted[fname] = None
            continue

        cipher_b64, hmac_b64, ts, cid = None, None, None, None
        try:
            cipher_b64, suffix = raw.split("::", 1)
            parts = suffix.split(":")
            if len(parts) >= 3:
                hmac_b64, ts, cid = parts[0], parts[1], parts[2]
        except:
            cipher_b64 = raw

        pt = aes_decrypt_base64(cipher_b64, SERVER_AES_KEY_HEX, AES_IV_HEX)
        hmac_ok = None
        if cid and cid in challenges:
            token = challenges[cid]["token"]
            msg = f"{fname}:{ts}:{token}"
            hmac_ok = verify_hmac(hmac_b64, msg, IBM_API_TOKEN)
        decrypted[fname] = {"value": pt, "hmac_valid": hmac_ok}

    return jsonify({"decrypted": decrypted})

# --- Serve frontend ---
@app.route("/")
def index():
    return send_from_directory(FRONTEND_FOLDER, "index.html")

@app.route("/<path:path>")
def static_proxy(path):
    return send_from_directory(FRONTEND_FOLDER, path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
