# integrity.py
import hashlib
import hmac
import os

def sha3_256_hash(data: bytes) -> str:
    h = hashlib.sha3_256()
    h.update(data)
    return h.hexdigest()

def make_hmac(key: bytes, data: bytes) -> str:
    """Return hex HMAC-SHA256"""
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def generate_hmac_key() -> bytes:
    return os.urandom(32)
