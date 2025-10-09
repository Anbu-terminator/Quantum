from flask import Flask, jsonify, send_from_directory, request, abort
import requests, base64, json, uuid, os
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from config import *
from quantum_key import get_quantum_challenge

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_FOLDER = os.path.join(BASE_DIR, "frontend")

app = Flask(__name__, static_folder=FRONTEND_FOLDER, static_url_path="")

challenges = {}

# --- AES decrypt ---
def aes_decrypt_base64(cipher_b64: str, key_hex: str, iv_hex: str) -> str:
    try:
        padding = '=' * (-len(cipher_b64) % 4)
        data = base64.urlsafe_b64decode(cipher_b64 + padding)
        key = unhexlify(key_hex)
        iv = unhexlify(iv_hex)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(data), AES.block_size)
        return pt.decode("utf-8")
    except Exception as e:
        return f"error:{e}"

# --- ThingSpeak fetch ---
def fetch_thingspeak_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": THINGSPEAK_READ_KEY, "results": 1}
    r = requests.get(url, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

# --- API: Quantum Challenge ---
@app.route("/api/challenge", methods=["GET"])
def challenge():
    if request.args.get("auth") != ESP_AUTH_TOKEN:
        abort(401)
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

        try:
            cipher_b64, cid, token = raw.split("::")
            pt = aes_decrypt_base64(cipher_b64, SERVER_AES_KEY_HEX, AES_IV_HEX)
        except:
            pt = raw
            cid = None
            token = None

        decrypted[fname] = {"value": pt, "challenge_id": cid, "challenge_token": token}

    return jsonify({"decrypted": decrypted})

# --- Serve frontend ---
@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def frontend(path):
    return send_from_directory(FRONTEND_FOLDER, path)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
