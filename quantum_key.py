# server/quantum_key.py
import math, time, threading, os, hashlib
from collections import OrderedDict
import requests
import config

# optional qiskit; if not available we fallback to os.urandom
try:
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator
    _QISKIT_AVAILABLE = True
except Exception:
    _QISKIT_AVAILABLE = False

# key_id -> {"key": bytes, "iv": bytes, "ts": float}
KEYS = OrderedDict()
CURRENT_KEY_ID = None
_LOCK = threading.Lock()


def _generate_key_bytes(num_bits=128):
    """Quantum (if available) or OS randomness to produce key bytes."""
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
            # if Qiskit call fails, fall through to os.urandom fallback
            pass
    return os.urandom((num_bits + 7) // 8)


# deterministic derivation for historical keys: SHA256(field2 + server_secret)
def derive_key_iv_from_keyid(key_id: str):
    """
    Deterministic mapping: SHA256( key_id || SERVER_AES_KEY_HEX ) -> 32 bytes
    first 16 bytes = AES key, next 16 bytes = IV (or CTR nonce fallback).
    This ensures we can deterministically re-create keys for historical entries.
    """
    secret = config.SERVER_AES_KEY_HEX or ""
    h = hashlib.sha256((str(key_id) + secret).encode("utf-8")).digest()
    return h[:16], h[16:32]


def preload_historical_keys(results=500):
    """
    Fetch ThingSpeak feeds and preload key entries into KEYS dict (keyed by key_id).
    Uses derive_key_iv_from_keyid to deterministically build key+iv per key_id.
    If ThingSpeak returns an error (bad token), this function raises a ValueError.
    """
    global CURRENT_KEY_ID
    url = f"https://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json"
    params = {"api_key": config.THINGSPEAK_READ_KEY, "results": results}
    try:
        r = requests.get(url, params=params, timeout=15)
        # if ThingSpeak returns a non-200, treat as bad_token
        if r.status_code != 200:
            raise ValueError(f"ThingSpeak returned HTTP {r.status_code}")
        j = r.json()
        # some ThingSpeak error responses can be strings or dicts without 'feeds'
        if not isinstance(j, dict) or "feeds" not in j:
            raise ValueError("ThingSpeak response missing 'feeds' — check read key")
        feeds = j.get("feeds", []) or []
        with _LOCK:
            for f in feeds:
                key_id = f.get("field2")
                if not key_id:
                    continue
                if key_id not in KEYS:
                    key_bytes, iv_bytes = derive_key_iv_from_keyid(key_id)
                    # If feed provides explicit iv/nonce fields, prefer those for stored iv/nonce:
                    # field3: iv_hex, field5: nonce_hex
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
            if KEYS:
                # set current to most recent key (last inserted)
                CURRENT_KEY_ID = next(reversed(KEYS))
        print("[quantum_key] preloaded historical keys:", len(KEYS))
    except Exception as e:
        # bubble up with useful message
        print("[quantum_key] preload_historical_keys error:", e)
        raise


def _rotate_loop(interval, keep):
    """Background rotator for generating new (quantum) keys for future feeds."""
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
    """
    Start background rotator and preload historical keys.
    If preload fails due to bad ThingSpeak token, this function will raise.
    """
    if interval is None:
        interval = getattr(config, "KEY_ROTATE_SECONDS", 60)
    if keep is None:
        keep = getattr(config, "KEEP_KEYS", 1000)

    # preload historical keys first (this will raise if bad token)
    preload_historical_keys(results=500)

    # start rotate loop (daemon)
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


def store_key(kid, key_bytes, iv_bytes):
    """Store a key (used by server when deriving/storing new key ids)"""
    with _LOCK:
        KEYS[kid] = {"key": key_bytes, "iv": iv_bytes, "ts": time.time()}
