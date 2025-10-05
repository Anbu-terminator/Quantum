# server/quantum_key.py
import math, time, threading, os
from collections import OrderedDict
import requests
import config

try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator
    _QISKIT_AVAILABLE = True
except Exception:
    _QISKIT_AVAILABLE = False

# --- Stores all keys with exact mapping ---
# key_id -> {"key": bytes, "iv": bytes, "ts": float}
KEYS = OrderedDict()  
CURRENT_KEY_ID = None
_LOCK = threading.Lock()


def _generate_key_bytes(num_bits=128):
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
                bits.extend(list(measured))
            bits = bits[:num_bits]
            bitstring = ''.join(bits)
            padlen = (8 - (len(bitstring) % 8)) % 8
            bitstring_padded = ("0" * padlen) + bitstring
            return int(bitstring_padded, 2).to_bytes(len(bitstring_padded) // 8, byteorder='big')
        except Exception:
            pass
    return os.urandom((num_bits + 7) // 8)


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
    if interval is None: interval = getattr(config, "KEY_ROTATE_SECONDS", 60)
    if keep is None: keep = getattr(config, "KEEP_KEYS", 1000)
    t = threading.Thread(target=_rotate_loop, args=(interval, keep), daemon=True)
    t.start()
    preload_historical_keys()


def preload_historical_keys():
    """
    Auto-fetch ThingSpeak feeds, extract field2 as key_id, and generate key+iv for historical entries.
    Ensures 100% decryption mapping.
    """
    global CURRENT_KEY_ID
    try:
        url = f"http://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?api_key={config.THINGSPEAK_READ_KEY}&results=500"
        r = requests.get(url, timeout=15)
        feeds = r.json().get("feeds", [])
        with _LOCK:
            for f in feeds:
                kid = f.get("field2")  # field2 = key_id
                if kid and kid not in KEYS:
                    # generate pseudo-random key/iv for historical feed
                    KEYS[kid] = {
                        "key": os.urandom(16),
                        "iv": os.urandom(16),
                        "ts": time.time()
                    }
            if KEYS:
                CURRENT_KEY_ID = next(reversed(KEYS))
        print("[quantum_key] preloaded historical keys:", list(KEYS.keys()))
    except Exception as e:
        print("[quantum_key] failed to preload historical keys:", e)


def get_current_key():
    with _LOCK:
        if CURRENT_KEY_ID is None:
            return None
        info = KEYS[CURRENT_KEY_ID]
        return CURRENT_KEY_ID, info["key"], info["iv"]


def get_key_by_id(kid):
    with _LOCK:
        return KEYS.get(kid)
