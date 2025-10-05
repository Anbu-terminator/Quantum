# server/quantum_key.py
import threading, time
from collections import OrderedDict
import os, hashlib

KEYS = OrderedDict()
CURRENT_KEY_ID = None
_LOCK = threading.Lock()

import requests
import config

def field2_to_aes_key_iv(field2: str):
    """
    Deterministic AES key + IV from field2 string.
    Ensures old feeds can be decrypted.
    """
    h = hashlib.sha256(field2.encode()).digest()
    return h[:16], h[16:32]

def preload_historical_keys(results=500):
    """
    Fetch historical ThingSpeak feeds and generate AES key/IV for each field2
    """
    global CURRENT_KEY_ID
    try:
        url = f"http://api.thingspeak.com/channels/{config.THINGSPEAK_CHANNEL_ID}/feeds.json?api_key={config.THINGSPEAK_READ_KEY}&results={results}"
        r = requests.get(url, timeout=15)
        feeds = r.json().get("feeds", [])
        with _LOCK:
            for f in feeds:
                field2 = f.get("field2")
                if field2 and field2 not in KEYS:
                    key, iv = field2_to_aes_key_iv(field2)
                    KEYS[field2] = {"key": key, "iv": iv, "ts": time.time()}
            if KEYS:
                CURRENT_KEY_ID = next(reversed(KEYS))
        print("[quantum_key] preloaded keys:", len(KEYS))
    except Exception as e:
        print("[quantum_key] preload failed:", e)

def _rotate_loop(interval, keep):
    global CURRENT_KEY_ID
    while True:
        try:
            # Generate new random key for current rotation
            key = os.urandom(16)
            iv = os.urandom(16)
            kid = str(int(time.time()))
            with _LOCK:
                KEYS[kid] = {"key": key, "iv": iv, "ts": time.time()}
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
    threading.Thread(target=_rotate_loop, args=(interval, keep), daemon=True).start()
    preload_historical_keys()

def get_current_key():
    with _LOCK:
        if CURRENT_KEY_ID is None:
            return None
        info = KEYS[CURRENT_KEY_ID]
        return CURRENT_KEY_ID, info["key"], info["iv"]

def get_key_by_id(kid):
    with _LOCK:
        return KEYS.get(kid)
