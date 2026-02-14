
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def gen_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()

def save_private_pem(priv: Ed25519PrivateKey, path: str):
    b = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(path, 'wb') as f:
        f.write(b)

def save_public_pem(priv: Ed25519PrivateKey, path: str):
    b = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(path, 'wb') as f:
        f.write(b)

def public_hex(priv: Ed25519PrivateKey) -> str:
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

def load_private_pem(path: str) -> Ed25519PrivateKey:
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def sign_b64(priv: Ed25519PrivateKey, msg: bytes) -> str:
    return base64.b64encode(priv.sign(msg)).decode('ascii')

def verify_b64(pub_hex: str, msg: bytes, sig_b64: str) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    sig = base64.b64decode(sig_b64.encode('ascii'))
    try:
        pub.verify(sig, msg)
        return True
    except Exception:
        return False
