
from blake3 import blake3
import hashlib

def blake3_hex(data: bytes) -> str:
    return blake3(data).hexdigest()

def sha3_256_hex(data: bytes) -> str:
    return hashlib.sha3_256(data).hexdigest()
