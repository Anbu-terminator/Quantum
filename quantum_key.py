# quantum_key.py
# Maintains a rotating store of "quantum" keys (16 bytes each).
# Uses qiskit if available, otherwise falls back to os.urandom.

import math
import time
import threading
import os
from collections import OrderedDict

# Try to use Qiskit/AerSimulator if installed; otherwise fallback
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
    """Return num_bits of randomness (as bytes). Prefer quantum if available."""
    if num_bits <= 0:
        return b""

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
                # measured is a string of bits
                bits.extend(list(measured))
            bits = bits[:num_bits]
            bitstring = ''.join(bits)
            padlen = (8 - (len(bitstring) % 8)) % 8
            bitstring_padded = ("0" * padlen) + bitstring
            b = int(bitstring_padded, 2).to_bytes(len(bitstring_padded) // 8, byteorder='big')
            return b
        except Exception:
            # fall through to os.urandom fallback
            pass

    # fallback using os.urandom
    bytelen = (num_bits + 7) // 8
    return os.urandom(bytelen)

def _rotate_loop(interval, keep):
    """Background thread: generate new key every `interval` seconds and keep last `keep` keys."""
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
    """Start background rotator thread. interval seconds, keep recent keys."""
    if interval is None:
        try:
            import config
            interval = getattr(config, "KEY_ROTATE_SECONDS", 60)
        except Exception:
            interval = 60
    if keep is None:
        try:
            import config
            keep = getattr(config, "KEEP_KEYS", 10)
        except Exception:
            keep = 10
    t = threading.Thread(target=_rotate_loop, args=(interval, keep), daemon=True)
    t.start()

def get_current_key():
    """Return (key_id, key_bytes, iv_bytes) for current key or None if none."""
    with _LOCK:
        if CURRENT_KEY_ID is None:
            return None
        info = KEYS[CURRENT_KEY_ID]
        return CURRENT_KEY_ID, info["key"], info["iv"]

def get_key_by_id(kid):
    """Return { key: bytes, iv: bytes, ts: float } or None."""
    with _LOCK:
        return KEYS.get(kid)
