# server/quantum_key.py
import math, time, threading
from collections import OrderedDict
from datetime import datetime
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

KEYS = OrderedDict()   # key_id -> { key: bytes, iv: bytes, ts: float }
CURRENT_KEY_ID = None
_LOCK = threading.Lock()

def _generate_key_bytes():
    num_bits = 128
    max_qubits = 25
    chunks = math.ceil(num_bits / max_qubits)
    bits = []
    for _ in range(chunks):
        qubits = min(max_qubits, num_bits - len(bits))
        qc = QuantumCircuit(qubits, qubits)
        qc.h(range(qubits))
        qc.measure(range(qubits), range(qubits))
        try:
            backend = AerSimulator()
            job = backend.run(qc, shots=1)
            res = job.result()
            counts = res.get_counts()
            measured = next(iter(counts.keys()))
            bits.extend(list(measured))
        except Exception:
            # fallback to pseudo-random
            import random
            for _ in range(qubits):
                bits.append(str(random.randint(0, 1)))
    bits = bits[:num_bits]
    bitstring = ''.join(bits)
    padlen = (8 - (len(bitstring) % 8)) % 8
    bstr = ("0" * padlen) + bitstring
    b = int(bstr, 2).to_bytes(len(bstr) // 8, byteorder='big')
    return b

def rotate_loop(interval=60, keep=10):
    global CURRENT_KEY_ID
    while True:
        key = _generate_key_bytes()[:16]
        iv = _generate_key_bytes()[:16]
        key_id = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        with _LOCK:
            KEYS[key_id] = {"key": key, "iv": iv, "ts": time.time()}
            CURRENT_KEY_ID = key_id
            while len(KEYS) > keep:
                KEYS.popitem(last=False)
        print(f"[keys] new key {key_id}")
        time.sleep(interval)

def start_rotator(interval=60, keep=10):
    t = threading.Thread(target=rotate_loop, args=(interval,keep), daemon=True)
    t.start()

def get_current_key():
    with _LOCK:
        if not CURRENT_KEY_ID:
            return None
        info = KEYS[CURRENT_KEY_ID]
        return CURRENT_KEY_ID, info["key"], info["iv"]

def get_key_by_id(kid):
    with _LOCK:
        return KEYS.get(kid)   # may be None
