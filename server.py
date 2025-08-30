from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import math, binascii, base64

# Qiskit imports
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
try:
    from qiskit_ibm_runtime import QiskitRuntimeService, Sampler
    IBM_AVAILABLE = True
except:
    IBM_AVAILABLE = False

app = Flask(__name__, static_folder="static", static_url_path="/")
CORS(app)

IBM_API_TOKEN = "XoyDUMzA1m8ECqxN17kPLA0tNqnFJe-O69ZMj5vR1j-n"

# Store latest ESP8266 data
ESP8266_DATA = {"status": "No data received yet."}

def qiskit_quantum_bits(num_bits=128, use_ibm=False):
    if num_bits <= 0: return b""
    max_qubits = 25
    chunks = math.ceil(num_bits / max_qubits)
    bits = []
    for _ in range(chunks):
        remaining = num_bits - len(bits)
        qubits = min(max_qubits, remaining)
        qc = QuantumCircuit(qubits, qubits)
        for q in range(qubits): qc.h(q)
        qc.measure(range(qubits), range(qubits))
        try:
            backend = AerSimulator()
            compiled = backend.run(qc, shots=1)
            counts = compiled.result().get_counts()
            bits.extend(list(next(iter(counts.keys()))))
        except:
            import random
            bits.extend(str(random.randint(0,1)) for _ in range(qubits))
    bits = bits[:num_bits]
    bitstring = ''.join(bits)
    padlen = (8 - (len(bitstring) % 8)) % 8
    bitstring_padded = ("0" * padlen) + bitstring
    return int(bitstring_padded,2).to_bytes(len(bitstring_padded)//8, byteorder='big')

@app.route("/api/random")
def api_random():
    bits = int(request.args.get("bits","128"))
    fmt = request.args.get("format","hex")
    use_ibm = request.args.get("ibm","0") in ("1","true","True") and IBM_API_TOKEN != ""
    if bits <=0 or bits>8192: return jsonify({"error":"bits must be 1-8192"}),400
    raw = qiskit_quantum_bits(bits,use_ibm)
    payload = base64.b64encode(raw).decode() if fmt=="b64" else binascii.hexlify(raw).decode()
    return jsonify({"bits_requested":bits,"format":fmt,"payload":payload})

@app.route("/api/cipher", methods=["POST"])
def api_cipher():
    if not request.is_json: return jsonify({"error":"expected JSON"}),400
    data = request.get_json()
    if "ciphertext" not in data: return jsonify({"error":"missing 'ciphertext'"}),400
    hexct = data["ciphertext"]
    try: ct = binascii.unhexlify(hexct)
    except Exception as e: return jsonify({"error":"invalid hex","detail":str(e)}),400
    return jsonify({"status":"ok","received_bytes":len(ct),"message":"Ciphertext received"}),200

# ESP8266 endpoints
@app.route("/api/esp8266", methods=["POST"])
def api_esp8266_post():
    global ESP8266_DATA
    if not request.is_json: return jsonify({"error":"expected JSON"}),400
    ESP8266_DATA = request.get_json()
    return jsonify({"status":"ok","stored":ESP8266_DATA})

@app.route("/api/esp8266", methods=["GET"])
def api_esp8266_get():
    return jsonify(ESP8266_DATA)

@app.route("/")
def index():
    return send_from_directory("static","index.html")

if __name__=="__main__":
    print("IBM available:",IBM_AVAILABLE)
    app.run(host="0.0.0.0",port=5000,debug=True)
