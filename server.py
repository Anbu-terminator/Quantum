# server.py
from flask import Flask, jsonify
import requests
import json
import config
from quantum_key import get_server_key_bytes
import hashlib
from Crypto.Cipher import AES
from base64 import b64decode

app = Flask(__name__)

TS_FEED_URL = f"https://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?results=5&api_key={config.THINGSPEAK_READ_KEY}"

def derive_session_key(server_key_bytes: bytes, nonce_bytes: bytes) -> bytes:
    # SHA-256(server_key || nonce) then take first 16 bytes
    h = hashlib.sha256()
    h.update(server_key_bytes)
    h.update(nonce_bytes)
    full = h.digest()
    return full[:16]

def pkcs7_unpad(b: bytes) -> bytes:
    if len(b) == 0:
        return b
    pad = b[-1]
    if pad < 1 or pad > 16:
        # invalid padding
        return b
    return b[:-pad]

def decrypt_aes_cbc(session_key: bytes, iv_hex: str, cipher_b64: str) -> str:
    iv = bytes.fromhex(iv_hex)
    cipher_bytes = b64decode(cipher_b64)
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    plain_padded = cipher.decrypt(cipher_bytes)
    plain = pkcs7_unpad(plain_padded)
    try:
        return plain.decode('utf-8')
    except:
        return plain.hex()

@app.route('/latest')
def latest():
    # fetch ThingSpeak channel recent feeds
    r = requests.get(TS_FEED_URL, timeout=10)
    if r.status_code != 200:
        return jsonify({"error": "failed fetch", "status": r.status_code}), 502

    data = r.json()
    feeds = data.get("feeds", [])
    out = []
    for feed in feeds:
        # expected layout:
        # field1 = key_id
        # field2 = temp_b64|ivTempHex
        # field3 = hum_b64|ivHumHex
        # field4 = ir_b64|ivIrHex
        # field5 = nonceHex
        key_id = feed.get("field1")
        field2 = feed.get("field2") or ""
        field3 = feed.get("field3") or ""
        field4 = feed.get("field4") or ""
        nonceHex = feed.get("field5") or ""

        entry = {"created_at": feed.get("created_at"), "key_id": key_id}

        # parse pairs
        def parse_pair(s):
            if '|' in s:
                a,b = s.split('|',1)
                return a,b
            return s, None

        temp_b64, ivTempHex = parse_pair(field2)
        hum_b64, ivHumHex = parse_pair(field3)
        ir_b64, ivIrHex = parse_pair(field4)

        # get server key bytes (may ignore key_id for now)
        server_key = get_server_key_bytes(key_id)

        try:
            nonce_bytes = bytes.fromhex(nonceHex)
        except:
            nonce_bytes = b'\x00'*16

        session_key = derive_session_key(server_key, nonce_bytes)

        # decrypt each (if possible)
        try:
            temp_plain = decrypt_aes_cbc(session_key, ivTempHex, temp_b64) if temp_b64 and ivTempHex else None
        except Exception as e:
            temp_plain = f"decrypt_error:{str(e)}"
        try:
            hum_plain = decrypt_aes_cbc(session_key, ivHumHex, hum_b64) if hum_b64 and ivHumHex else None
        except Exception as e:
            hum_plain = f"decrypt_error:{str(e)}"
        try:
            ir_plain = decrypt_aes_cbc(session_key, ivIrHex, ir_b64) if ir_b64 and ivIrHex else None
        except Exception as e:
            ir_plain = f"decrypt_error:{str(e)}"

        entry.update({
            "temperature_encrypted": temp_b64,
            "temperature_iv": ivTempHex,
            "temperature": temp_plain,
            "humidity_encrypted": hum_b64,
            "humidity_iv": ivHumHex,
            "humidity": hum_plain,
            "ir_encrypted": ir_b64,
            "ir_iv": ivIrHex,
            "ir": ir_plain,
            "nonce": nonceHex
        })
        out.append(entry)

    return jsonify({"feeds_decrypted": out})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
