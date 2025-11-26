# encryption.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_aes_key() -> bytes:
    """Return a new 32-byte AES key (AES-256)."""
    return AESGCM.generate_key(bit_length=256)

def aes_encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt plaintext with AES-GCM.
    Returns dict: {'ciphertext', 'nonce', 'tag' (appended in ciphertext by AESGCM), 'key'}
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {"ciphertext": ciphertext, "nonce": nonce}

def aes_decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> bytes:
    """Decrypt AES-GCM ciphertext."""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext
