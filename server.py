from flask import Flask, jsonify, request, send_from_directory
import os, binascii, requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from qiskit_ibm_runtime import QiskitRuntimeService, Sampler
from config import *

app = Flask(__name__, static_folder="../frontend", static_url_path="")

# ---------------- Helper functions ----------------
def hx(s):
    return binascii.unhexlify(s)

def aes_decrypt_hex(iv_hex, cipher_hex, key_hex):
    iv = hx(iv_hex)
    ct = hx(cipher_hex)
    key = hx(key_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, AES.block_size)
    except ValueError:
        pass
    return pt.decode('utf-8', errors='replace')

# --------------- Serve frontend -----------------
@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(app.static_folder, path)

# --------------- Quantum Nonce ------------------
@app.route("/quantum_nonce", methods=["GET"])
def quantum_nonce():
    token = request.args.get("token", "")
    if token != ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    n_bytes = int(request.args.get("n", 16))
    try:
        svc = QiskitRuntimeService(channel="ibm_quantum", token=IBM_API_TOKEN)
        sampler = Sampler(service=svc)
        from qiskit import QuantumCircuit
        bits_needed = n_bytes*8
        chunks = (bits_needed+7)//8
        combined = ''
        for _ in range(chunks):
            qc = QuantumCircuit(8,8)
            qc.h(range(8))
            qc.measure(range(8), range(8))
            job = sampler.run(qc, shots=1)
            res = job.result()
            bitstr = list(res.counts().keys())[0]
            combined += bitstr
        combined = combined[:bits_needed]
        b = int(combined,2).to_bytes(n_bytes, 'big')
        return jsonify({"status":"ok","nonce_hex":binascii.hexlify(b).decode()})
    except Exception as e:
        fallback = os.urandom(n_bytes)
        return jsonify({"status":"fallback","nonce_hex":binascii.hexlify(fallback).decode(),"error":str(e)})

# --------------- Decrypt ThingSpeak ------------------
@app.route("/decrypt_latest", methods=["GET"])
def decrypt_latest():
    url = f"https://api.thingspeak.com/channels/{THINGSPEAK_CHANNEL_ID}/feeds.json?results=1&api_key={THINGSPEAK_READ_KEY}"
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        return jsonify({"error": "ThingSpeak fetch failed"}), 502
    data = r.json()
    feeds = data.get("feeds", [])
    if not feeds:
        return jsonify({"error":"no feeds"}), 404
    latest = feeds[0]
    out = {}
    for i in range(1,6):
        field_key = f"field{i}"
        raw = latest.get(field_key)
        if raw is None:
            out[field_key] = None
            continue
        raw = raw.strip()
        if ":" in raw:
            iv_hex, cipher_hex = raw.split(":",1)
            try:
                pt = aes_decrypt_hex(iv_hex, cipher_hex, SERVER_AES_KEY_HEX)
                out[field_key] = pt
            except Exception as e:
                out[field_key] = {"error":"decrypt_failed","detail":str(e),"raw":raw}
        else:
            out[field_key] = {"error":"unexpected_format","raw":raw}
    return jsonify({"status":"ok","data":out,"created_at":latest.get("created_at")})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
