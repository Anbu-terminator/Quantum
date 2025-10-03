from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import requests
import os
import base64
import json
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from qiskit import QuantumCircuit, Aer, execute
import config

# Flask app
app = Flask(__name__)
CORS(app)

# MongoDB
client = MongoClient(config.MONGODB_URI)
db = client["QuantumESP"]
collection = db["SensorData"]

# In-memory key storage
quantum_key_store = {}

# --- Quantum Key Generation ---
def generate_quantum_key():
    qc = QuantumCircuit(4, 4)
    qc.h(range(4))
    qc.measure(range(4), range(4))
    backend = Aer.get_backend("qasm_simulator")
    result = execute(qc, backend, shots=1).result()
    counts = result.get_counts()
    key_bin = list(counts.keys())[0]
    key_hex = hex(int(key_bin, 2))[2:].zfill(32)  # 16 bytes
    return key_hex[:32], secrets.token_hex(16)  # key + iv

@app.route("/api/quantum_key", methods=["GET"])
def get_quantum_key():
    auth = request.args.get("auth")
    if auth != config.ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    key, iv = generate_quantum_key()
    quantum_key_store["latest"] = {"key": key, "iv": iv}
    return jsonify({"key": key, "iv": iv})

# --- Upload Encrypted Sensor Data ---
@app.route("/api/upload", methods=["POST"])
def upload():
    data = request.get_json()
    if not data or data.get("token") != config.ESP_AUTH_TOKEN:
        return jsonify({"error": "unauthorized"}), 401

    cipher_b64 = data.get("cipher_b64")
    iv_hex = data.get("iv")
    if not cipher_b64 or not iv_hex:
        return jsonify({"error": "missing fields"}), 400

    # Decode values
    cipher_bytes = base64.b64decode(cipher_b64)
    iv = bytes.fromhex(iv_hex)
    key_hex = quantum_key_store.get("latest", {}).get("key")
    if not key_hex:
        return jsonify({"error": "no key"}), 500
    key = bytes.fromhex(key_hex)

    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plain = unpad(cipher.decrypt(cipher_bytes), AES.block_size)
        sensor_data = json.loads(plain.decode("utf-8"))
    except Exception as e:
        return jsonify({"error": f"decryption failed: {str(e)}"}), 500

    # Store in MongoDB
    collection.insert_one(sensor_data)

    # Optionally push to ThingSpeak
    if data.get("post_to_thingspeak", False):
        try:
            requests.post(
                "http://api.thingspeak.com/update",
                data={
                    "api_key": config.THINGSPEAK_WRITE_KEY,
                    "field1": sensor_data.get("temperature"),
                    "field2": sensor_data.get("humidity"),
                },
                timeout=5,
            )
        except Exception as e:
            print("ThingSpeak push failed:", e)

    return jsonify({"status": "ok", "data": sensor_data})

# --- Root ---
@app.route("/")
def home():
    return "Quantum ESP Backend Running (HTTP - Insecure)"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
