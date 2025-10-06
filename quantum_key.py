# backend/quantum_key.py
import math, time, threading, os
from collections import OrderedDict
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

KEYS = OrderedDict()
CURRENT_KEY_ID = None
_LOCK = threading.Lock()

def _generate_key_bytes(num_bits=128):
    if num_bits <= 0:
        return b""
    max_qubits = 25
    chunks = math.ceil(num_bits / max_qubits)
    bits = []
    for _ in range(chunks):
        qubits = min(max_qubits, num_bits - len(bits))
        qc = QuantumCircuit(qubits, qubits)
        for q in range(qubits):
            qc.h(q)
        qc.measure(range(qubits), range(qubits))
        try:
            backend = AerSimulator()
            job = backend.run(qc, shots=1)
            res = job.result()
            counts = res.get_counts()
            measured = next(iter(counts.keys()))
            bits.extend(list(measured))
        except Exception:
            import random
            for _ in range(qubits):
                bits.append(str(random.randint(0,1)))
    bits = bits[:num_bits]
    bitstring = ''.join(bits)
    padlen = (8 - (len(bitstring) % 8)) % 8
    bitstring_padded = ("0" * padlen) + bitstring
    b = int(bitstring_padded, 2).to_bytes(len(bitstring_padded) // 8, byteorder='big')
    return b

def _rotate_loop(interval, keep):
    global CURRENT_KEY_ID
    while True:
        key_bytes = _generate_key_bytes(128)[:16]
        iv = os.urandom(16)
        kid = str(int(time.time()))
        with _LOCK:
            KEYS[kid] = {"key": key_bytes, "iv": iv, "ts": time.time()}
            CURRENT_KEY_ID = kid
            while len(KEYS) > keep:
                KEYS.popitem(last=False)
        print("[quantum_key] rotated key_id:", kid)
        time.sleep(interval)

def start_rotator(interval=None, keep=None):
    if interval is None: interval = 60
    if keep is None: keep = 10
    t = threading.Thread(target=_rotate_loop, args=(interval, keep), daemon=True)
    t.start()

def get_current_key():
    with _LOCK:
        if CURRENT_KEY_ID is None:
            return None
        info = KEYS[CURRENT_KEY_ID]
        return CURRENT_KEY_ID, info["key"], info["iv"]

def get_key_by_id(kid):
    with _LOCK:
        return KEYS.get(kid)
