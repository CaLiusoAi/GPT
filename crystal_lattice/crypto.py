
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def load_private_key_pem(path: str) -> Ed25519PrivateKey:
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key_hex(hexstr: str) -> Ed25519PublicKey:
    b = bytes.fromhex(hexstr)
    return Ed25519PublicKey.from_public_bytes(b)

def private_key_to_public_hex(priv: Ed25519PrivateKey) -> str:
    pub = priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return pub.hex()

def sign_b64(priv: Ed25519PrivateKey, msg: bytes) -> str:
    sig = priv.sign(msg)
    return base64.b64encode(sig).decode('ascii')

def verify_b64(pub: Ed25519PublicKey, msg: bytes, sig_b64: str) -> bool:
    sig = base64.b64decode(sig_b64.encode('ascii'))
    try:
        pub.verify(sig, msg)
        return True
    except Exception:
        return False

def gen_keypair_pem(priv_path: str, pub_path: str):
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(priv_path, 'wb') as f:
        f.write(priv_bytes)
    with open(pub_path, 'wb') as f:
        f.write(pub)
    return priv
