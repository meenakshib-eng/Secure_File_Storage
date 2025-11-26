# key_management.py
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

KEY_DIR = "keys"
PRIVATE_KEY_FILE = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, "public_key.pem")

def generate_rsa_keypair(bits: int = 2048, overwrite: bool = False):
    import os
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR, exist_ok=True)
    if os.path.exists(PRIVATE_KEY_FILE) and not overwrite:
        raise FileExistsError("RSA keypair already exists; pass overwrite=True to replace.")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = private_key.public_key()

    # Store private key (PEM)
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    # Store public key (PEM)
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return PRIVATE_KEY_FILE, PUBLIC_KEY_FILE

def load_public_key(path: str):
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key(path: str):
    from cryptography.hazmat.primitives import serialization
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def wrap_key(aes_key: bytes, public_key) -> bytes:
    """Wrap AES key with RSA public key using OAEP."""
    wrapped = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return wrapped

def unwrap_key(wrapped_key: bytes, private_key) -> bytes:
    """Unwrap AES key with RSA private key."""
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return aes_key
