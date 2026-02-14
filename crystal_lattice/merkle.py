
from typing import List, Tuple
import hashlib

def _h(x: bytes) -> bytes:
    return hashlib.sha3_256(x).digest()

def leaf_hash(leaf_bytes: bytes) -> bytes:
    return _h(b'leaf:' + leaf_bytes)

def node_hash(left: bytes, right: bytes) -> bytes:
    return _h(b'node:' + left + right)

def merkle_root(leaves: List[bytes]) -> bytes:
    if not leaves:
        return _h(b'empty')
    level = [leaf_hash(x) for x in leaves]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i+1 == len(level):
                nxt.append(node_hash(level[i], level[i]))
            else:
                nxt.append(node_hash(level[i], level[i+1]))
        level = nxt
    return level[0]

def inclusion_proof(leaves: List[bytes], index: int) -> List[bytes]:
    # returns sibling hashes from leaf to root
    if index < 0 or index >= len(leaves):
        raise IndexError('leaf index out of range')
    level = [leaf_hash(x) for x in leaves]
    proof = []
    idx = index
    while len(level) > 1:
        if idx % 2 == 0:
            sib = level[idx+1] if idx+1 < len(level) else level[idx]
        else:
            sib = level[idx-1]
        proof.append(sib)
        # build next level
        nxt = []
        for i in range(0, len(level), 2):
            if i+1 == len(level):
                nxt.append(node_hash(level[i], level[i]))
            else:
                nxt.append(node_hash(level[i], level[i+1]))
        level = nxt
        idx //= 2
    return proof

def verify_inclusion(leaf_bytes: bytes, index: int, proof: List[bytes], root: bytes, tree_size: int) -> bool:
    # note: tree_size used only for sanity here
    h = leaf_hash(leaf_bytes)
    idx = index
    for sib in proof:
        if idx % 2 == 0:
            h = node_hash(h, sib)
        else:
            h = node_hash(sib, h)
        idx //= 2
    return h == root
