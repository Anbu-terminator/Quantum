# server.py
from flask import Flask, request, jsonify, abort
import requests
import binascii
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from qiskit_ibm_runtime import QiskitRuntimeService, Sampler, Session
import config

app = Flask(__name__)

# Helper: hex -> bytes
def hx(s):
    return binascii.unhexlify(s)

# Helper: AES-128-CBC decrypt; expects iv (16 bytes) and ciphertext bytes
def aes_decrypt_hex(iv_hex, cipher_hex, key_hex):
    iv = hx(iv_hex)
    ct = hx(cipher_hex)
    key = hx(key_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    try:
        pt = unpad(pt, AES.block_size)
    except ValueError:
        # If padding fails, still return raw bytes as fallback
        pass
    return pt.decode('utf-8', errors='replace')

# Endpoint: serve quantum nonce(s)
@app.route('/quantum_nonce', methods=['GET'])
def quantum_nonce():
    # simple auth: expect ?token=ESP_AUTH_TOKEN
    token = request.args.get('token', '')
    if token != config.ESP_AUTH_TOKEN:
        abort(401)
    # number of bytes requested (default 16)
    n_bytes = int(request.args.get('n', 16))
    # Use Qiskit Runtime Service to sample n_bytes worth of bits.
    # We'll generate n_bytes * 8 random bits by measuring qubits in H-basis.
    # NOTE: Service requires qiskit-ibm-runtime package and valid IBM_API_TOKEN.
    try:
        svc = QiskitRuntimeService(channel="ibm_quantum", token=config.IBM_API_TOKEN)
        # Use Sampler to sample single-qubit H circuits repeated to get bits.
        sampler = Sampler(service=svc)
        # We will create a circuit that applies H on n_qubits and measure
        # but Sampler can be used with options; for simplicity, use sampler.run
        # We'll create enough qubits to get n_bytes*8 bits in one shot or multiple shots.
        # To keep runtime short, sample 8-bit chunks per shot.
        bits_needed = n_bytes * 8
        # We'll sample 8 qubits at a time and do ceil(bits_needed/8) shots
        chunks = (bits_needed + 7) // 8
        all_bits = []
        from qiskit import QuantumCircuit
        for _ in range(chunks):
            qc = QuantumCircuit(8, 8)
            qc.h(range(8))
            qc.measure(range(8), range(8))
            job = sampler.run(qc, shots=1)  # one shot returns 8 bits
            res = job.result()
            counts = res.counts()
            # counts keys are bitstrings like '00010101'; get the key
            bitstr = list(counts.keys())[0]
            # append LSB-first or MSB? Qiskit uses order that match counts (big-endian).
            all_bits.append(bitstr)
        combined = ''.join(all_bits)[:bits_needed]
        # convert bits to bytes
        b = int(combined, 2).to_bytes(n_bytes, 'big')
        return jsonify({"status": "ok", "nonce_hex": binascii.hexlify(b).decode()})
    except Exception as e:
        # If quantum service fails (rate limits/availability), fallback to os.urandom
        fallback = os.urandom(n_bytes)
        return jsonify({"status": "fallback", "nonce_hex": binascii.hexlify(fallback).decode(), "error": str(e)})

# Endpoint: decrypt latest ThingSpeak feed and return plaintext
@app.route('/decrypt_latest', methods=['GET'])
def decrypt_latest():
    # no auth for frontend; you can add auth if desired
    channel = config.THINGSPEAK_CHANNEL_ID
    read_key = config.THINGSPEAK_READ_KEY
    url = f"https://api.thingspeak.com/channels/{channel}/feeds.json?results=1&api_key={read_key}"
    r = requests.get(url, timeout=10)
    if r.status_code != 200:
        return jsonify({"error": "ThingSpeak fetch failed", "status_code": r.status_code}), 502
    data = r.json()
    feeds = data.get('feeds', [])
    if not feeds:
        return jsonify({"error": "no feeds"}), 404
    latest = feeds[0]
    # Fields: field1..field5
    out = {}
    for i in range(1, 6):
        field_key = f'field{i}'
        raw = latest.get(field_key)
        if raw is None:
            out[field_key] = None
            continue
        raw = raw.strip()
        # Expect form ivhex:cipherhex
        if ':' in raw:
            iv_hex, cipher_hex = raw.split(':', 1)
            try:
                pt = aes_decrypt_hex(iv_hex, cipher_hex, config.SERVER_AES_KEY_HEX)
                out[field_key] = pt
            except Exception as e:
                out[field_key] = {"error": "decrypt_failed", "detail": str(e), "raw": raw}
        else:
            out[field_key] = {"error": "unexpected_format", "raw": raw}
    return jsonify({"status":"ok", "data": out, "created_at": latest.get('created_at')})

if __name__ == '__main__':
    app.run(host=config.SERVER_HOST, port=config.SERVER_PORT, debug=True)
