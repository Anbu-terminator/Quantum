# quantum_key.py
from binascii import unhexlify
import config

def get_server_key_bytes(key_id: str = None) -> bytes:
    """
    Return the 16-byte server key used to derive session keys.
    Currently uses SERVER_AES_KEY_HEX from config.py.
    If you have multiple keys keyed by key_id, extend this to return the one matching key_id.
    """
    hexs = config.SERVER_AES_KEY_HEX
    return unhexlify(hexs)
