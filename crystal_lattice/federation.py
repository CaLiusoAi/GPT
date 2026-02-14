
from typing import Dict, Any, List
from .merkle import verify_inclusion

def compute_quorum(attestations: List[Dict[str, Any]], min_quorum: int = 3) -> Dict[str, Any]:
    # attestations must agree on row_digest
    if not attestations:
        return {'status': 'insufficient_witnesses', 'quorum_strength': 0, 'row_digest': None}
    row = attestations[0]['row_digest']
    agree = [a for a in attestations if a.get('row_digest') == row and a.get('status') == 'admissible']
    if len(agree) >= min_quorum:
        return {'status': 'admissible', 'quorum_strength': len(agree), 'row_digest': row}
    return {'status': 'insufficient_witnesses', 'quorum_strength': len(agree), 'row_digest': row}

def gossip_conflict_detected(sths: List[Dict[str, Any]]) -> bool:
    # simplistic: conflict if any same tree_size with different root_hash
    seen = {}
    for s in sths:
        ts = int(s.get('tree_size', -1))
        rh = s.get('root_hash')
        if ts in seen and seen[ts] != rh:
            return True
        seen[ts] = rh
    return False
