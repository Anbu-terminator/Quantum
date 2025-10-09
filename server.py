# backend/server.py
from flask import Flask, jsonify, request, abort
import requests, base64, json, threading, uuid
from binascii import unhexlify
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import HMAC, SHA256
from config import *
from ibm_runtime import submit_quantum_job, retrieve_job_result

app = Flask(__name__)

# In-memory challenges storage
challenges = {}

TS_CHANNEL_FEEDS_URL = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json"

def aes_decrypt_base64(cipher_b64: str, key_hex: str, iv_hex: str) -> str:
    try:
        data = base64.b64decode(cipher_b64)
        key = unhexlify(key_hex)
        iv = unhexlify(iv_hex)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(data), AES.block_size)
        return pt.decode('utf-8')
    except:
        return None

def verify_hmac(hmac_b64: str, message: str, key: str) -> bool:
    try:
        expected = HMAC.new(key.encode('utf-8'), digestmod=SHA256)
        expected.update(message.encode('utf-8'))
        exp_b = base64.urlsafe_b64encode(expected.digest()).decode('utf-8').rstrip('=')
        return hmac_b64 == exp_b
    except:
        return False

def background_quantum_runner(challenge_id: str, job_obj):
    try:
        proof = retrieve_job_result(job_obj)
        challenges[challenge_id]["proof"] = proof
        challenges[challenge_id]["status"] = "done"
    except Exception as e:
        challenges[challenge_id]["status"] = "failed"
        challenges[challenge_id]["proof"] = {"error": str(e)}

@app.route('/quantum/challenge', methods=['GET'])
def create_challenge():
    challenge_id = str(uuid.uuid4())
    challenge_token = base64.urlsafe_b64encode(uuid.uuid4().bytes).decode('utf-8').rstrip('=')
    challenges[challenge_id] = {"token": challenge_token, "status": "pending"}

    try:
        job_info = submit_quantum_job()
        job_id = job_info.get('job_id')
        challenges[challenge_id]["job_id"] = job_id
        t = threading.Thread(target=background_quantum_runner, args=(challenge_id, job_info.get('internal_job')), daemon=True)
        t.start()
    except Exception as e:
        challenges[challenge_id]["status"] = "failed"
        challenges[challenge_id]["error"] = str(e)
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "challenge_id": challenge_id, "challenge_token": challenge_token})

@app.route('/quantum/status/<challenge_id>', methods=['GET'])
def challenge_status(challenge_id):
    ch = challenges.get(challenge_id)
    if not ch:
        return jsonify({"ok": False, "error": "not found"}), 404
    return jsonify({"ok": True, "challenge": ch})

def fetch_thingspeak_latest():
    params = {'results': THINGSPEAK_RESULTS, 'api_key': THINGSPEAK_READ_KEY}
    r = requests.get(TS_CHANNEL_FEEDS_URL, params=params, timeout=10)
    r.raise_for_status()
    return r.json()

@app.route('/feeds/latest', methods=['GET'])
def latest_decrypted_feed():
    token = request.args.get('auth')
    if token and token != ESP_AUTH_TOKEN:
        abort(401)
    data = fetch_thingspeak_latest()
    feeds = data.get('feeds', [])
    if not feeds:
        return jsonify({"error": "no feeds"}), 404
    feed = feeds[-1]

    names = {'field1':'Label1','field2':'Temperature','field3':'Humidity','field4':'IR','field5':'Label2'}
    decrypted = {}

    for fkey, fname in names.items():
        raw = feed.get(fkey)
        if not raw:
            decrypted[fname] = None
            continue
        cipher_b64, hmac_b64, ts, challenge_id = None, None, None, None
        if "::" in raw:
            cipher_b64, suffix = raw.split("::",1)
            parts = suffix.split(":")
            if len(parts)>=3:
                hmac_b64 = parts[0]; ts=parts[1]; challenge_id=parts[2]
            else: hmac_b64=parts[0] if parts else None
        else:
            cipher_b64 = raw

        plaintext = aes_decrypt_base64(cipher_b64, SERVER_AES_KEY_HEX, AES_IV_HEX)
        hmac_ok, challenge_info = None, None
        if challenge_id:
            challenge_info = challenges.get(challenge_id)
            if challenge_info:
                challenge_token = challenge_info.get('token')
                message = f"{fname}:{ts}:{challenge_token}"
                if hmac_b64: hmac_ok = verify_hmac(hmac_b64, message, IBM_API_TOKEN)
                else: hmac_ok = False
            else: hmac_ok=False

        decrypted[fname] = {"value": plaintext, "hmac_valid": hmac_ok, "challenge_id": challenge_id, "challenge": challenge_info}

    return jsonify({"decrypted": decrypted, "_raw_feed": feed})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
