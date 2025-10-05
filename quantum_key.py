# quantum_key.py
import math, time, threading, os
from collections import OrderedDict

# Try qiskit; fallback to os.urandom if not available
try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator
    _QISKIT_AVAILABLE = True
except Exception:
    _QISKIT_AVAILABLE = False

KEYS = OrderedDict()   # key_id -> { key: bytes, iv: bytes, ts: float }
CURRENT_KEY_ID = None
_LOCK = threading.Lock()

def _generate_key_bytes(num_bits=128):
    if num_bits <= 0:
        return b""
    # prefer quantum if available
    if _QISKIT_AVAILABLE:
        try:
            max_qubits = 25
            chunks = math.ceil(num_bits / max_qubits)
            bits = []
            for _ in range(chunks):
                remaining = num_bits - len(bits)
                qubits = min(max_qubits, remaining)
                qc = QuantumCircuit(qubits, qubits)
                qc.h(range(qubits))
                qc.measure(range(qubits), range(qubits))
                backend = AerSimulator()
                job = backend.run(qc, shots=1)
                res = job.result()
                counts = res.get_counts()
                measured = next(iter(counts.keys()))
                bits.extend(list(measured))
            bits = bits[:num_bits]
            bitstring = ''.join(bits)
            padlen = (8 - (len(bitstring) % 8)) % 8
            bitstring_padded = ("0" * padlen) + bitstring
            b = int(bitstring_padded, 2).to_bytes(len(bitstring_padded) // 8, byteorder='big')
            return b
        except Exception:
            pass
    # fallback
    bytelen = (num_bits + 7) // 8
    return os.urandom(bytelen)

def _rotate_loop(interval, keep):
    global CURRENT_KEY_ID
    while True:
        try:
            key_bytes = _generate_key_bytes(128)[:16]
            iv = os.urandom(16)
            kid = str(int(time.time()))
            with _LOCK:
                KEYS[kid] = {"key": key_bytes, "iv": iv, "ts": time.time()}
                CURRENT_KEY_ID = kid
                while len(KEYS) > keep:
                    KEYS.popitem(last=False)
            print("[quantum_key] rotated key_id:", kid)
        except Exception as e:
            print("[quantum_key] rotate error:", e)
        time.sleep(interval)

def start_rotator(interval=None, keep=None):
    import config
    if interval is None: interval = getattr(config, "KEY_ROTATE_SECONDS", 60)
    if keep is None: keep = getattr(config, "KEEP_KEYS", 1000)
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

# quantum_key.py (add at the bottom)
def get_all_keys():
    """Return a list of all keys in the rotator"""
    with _LOCK:
        return [{"key_id": kid, "key": info["key"], "iv": info["iv"]} for kid, info in KEYS.items()]

