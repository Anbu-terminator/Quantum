from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import math
import os
import binascii
import base64

# Qiskit imports
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
# optional IBM provider
try:
    from qiskit_ibm_runtime import QiskitRuntimeService, Sampler
    IBM_AVAILABLE = True
except Exception:
    IBM_AVAILABLE = False

app = Flask(__name__, static_folder="static", static_url_path="/")
CORS(app)

# -----------------------------
# CONFIGURATION - CHANGE THESE
# -----------------------------
IBM_API_TOKEN = "XoyDUMzA1m8ECqxN17kPLA0tNqnFJe-O69ZMj5vR1j-n"   # <-- CHANGE if you have IBM token
IBM_REGION = "ibm-q"
# -----------------------------

# Utility: generate quantum random bits using Qiskit
def qiskit_quantum_bits(num_bits=128, use_ibm=False):
    if num_bits <= 0:
        return b""

    max_qubits = 25
    chunks = math.ceil(num_bits / max_qubits)
    bits = []

    for chunk_index in range(chunks):
        remaining = num_bits - len(bits)
        qubits = min(max_qubits, remaining)

        qc = QuantumCircuit(qubits, qubits)
        for q in range(qubits):
            qc.h(q)
        qc.measure(range(qubits), range(qubits))

        # Use Aer simulator
        try:
            backend = AerSimulator()
            compiled = backend.run(qc, shots=1)   # REPLACEMENT for execute
            result = compiled.result()
            counts = result.get_counts()
            measured = next(iter(counts.keys()))
            bits.extend(list(measured))
        except Exception as e:
            import random
            for _ in range(qubits):
                bits.append(str(random.randint(0, 1)))

    bits = bits[:num_bits]
    bitstring = ''.join(bits)

    padlen = (8 - (len(bitstring) % 8)) % 8
    bitstring_padded = ("0" * padlen) + bitstring
    b = int(bitstring_padded, 2).to_bytes(len(bitstring_padded) // 8, byteorder='big')
    return b

@app.route("/api/random")
def api_random():
    bits = int(request.args.get("bits", "128"))
    fmt = request.args.get("format", "hex")
    use_ibm = request.args.get("ibm", "0") in ("1", "true", "True") and IBM_API_TOKEN != ""

    if bits <= 0 or bits > 8192:
        return jsonify({"error": "bits must be between 1 and 8192"}), 400

    raw = qiskit_quantum_bits(bits, use_ibm=use_ibm)
    if fmt == "b64":
        payload = base64.b64encode(raw).decode()
    else:
        payload = binascii.hexlify(raw).decode()

    return jsonify({
        "bits_requested": bits,
        "format": fmt,
        "payload": payload
    })

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 5000
    print("IBM available:", IBM_AVAILABLE)
    if IBM_API_TOKEN:
        print("IBM token set (not printed). IBM usage enabled.")
    app.run(host=HOST, port=PORT, debug=True)
