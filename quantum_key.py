# server/quantum_key.py
import math, time, threading, os, hashlib
from collections import OrderedDict
import requests
import config

# optional qiskit usage (kept for your quantum project)
try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator
    _QISKIT_AVAILABLE = True
except Exception:
    _QISKIT_AVAILABLE = False

KEYS = OrderedDict()   # key_id -> {"key": bytes, "iv": bytes, "ts": float}
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

def derive_key_iv_from_keyid(key_id: str):
    """
    Deterministically derive AES key + IV from key_id + server secret.
    Returns (key_bytes (16), iv_bytes (16)).
    """
    secret = config.SERVER_AES_KEY_HEX or ""
    h = hashlib.sha256((str(key_id) + secret).encode("utf-8")).digest()
    return h[:16], h[16:32]

def preload_historical_keys(results=500):
    """
    Fetch ThingSpeak feeds and preload deterministic key/iv for each unique field2.
    If ThingSpeak returns an error (bad token), returns (False, message).
    On success returns (True, number_of_keys_preloaded).
    """
    url = "https://api.thingspeak.com/channels/{}/feeds.json".format(config.THINGSPEAK_CHANNEL_ID)
    params = {"api_key": config.THINGSPEAK_READ_KEY, "results": results}
    try:
        r = requests.get(url, params=params, timeout=15)
    except Exception as e:
        return False, f"fetch_failed: {e}"

    if r.status_code != 200:
        return False, f"bad_token_or_http_{r.status_code}"

    try:
        j = r.json()
    except Exception:
        return False, "invalid_json_response"

    if not isinstance(j, dict) or "feeds" not in j:
        return False, "missing_feeds_in_response"

    feeds = j.get("feeds", []) or []
    with _LOCK:
        added = 0
        for f in feeds:
            key_id = (f.get("field2") or "").strip()
            if not key_id:
                continue
            if key_id in KEYS:
                continue
            key_bytes, iv_bytes = derive_key_iv_from_keyid(key_id)
            # prefer iv from feed field3 or field5 if present (hex)
            field3 = (f.get("field3") or "").strip()
            field5 = (f.get("field5") or "").strip()
            if field3:
                try:
                    iv_bytes = bytes.fromhex(field3)
                except Exception:
                    pass
            elif field5:
                try:
                    iv_bytes = bytes.fromhex(field5)
                except Exception:
                    pass
            KEYS[key_id] = {"key": key_bytes, "iv": iv_bytes, "ts": time.time()}
            added += 1
        if KEYS:
            # current to the most recently inserted key
            global CURRENT_KEY_ID
            CURRENT_KEY_ID = next(reversed(KEYS))
    return True, added

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
    if interval is None:
        interval = getattr(config, "KEY_ROTATE_SECONDS", 60)
    if keep is None:
        keep = getattr(config, "KEEP_KEYS", 1000)

    ok, info = preload_historical_keys(results=500)
    if not ok:
        # preload failed — return info so caller can log and react
        raise RuntimeError(f"preload_historical_keys failed: {info}")
    # start rotation
    t = threading.Thread(target=_rotate_loop, args=(interval, keep), daemon=True)
    t.start()
    return True

def get_current_key():
    with _LOCK:
        if CURRENT_KEY_ID is None:
            return None
        info = KEYS[CURRENT_KEY_ID]
        return CURRENT_KEY_ID, info["key"], info["iv"]

def get_key_by_id(kid):
    with _LOCK:
        return KEYS.get(kid)

def store_key(kid, key_bytes, iv_bytes):
    with _LOCK:
        KEYS[kid] = {"key": key_bytes, "iv": iv_bytes, "ts": time.time()}
