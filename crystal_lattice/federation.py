
from typing import Dict, Any, List

def gossip_conflict_detected(sths: List[Dict[str, Any]]) -> bool:
    seen = {}
    for s in sths:
        ts = int(s.get('tree_size', -1))
        rh = s.get('root_hash')
        if ts in seen and seen[ts] != rh:
            return True
        seen[ts] = rh
    return False

def compute_quorum(attestations: List[Dict[str, Any]], min_quorum: int = 3) -> Dict[str, Any]:
    if not attestations:
        return {'status': 'insufficient_witnesses', 'quorum_strength': 0, 'row_digest': None}
    target = attestations[0].get('row_digest')
    ok = [a for a in attestations if a.get('row_digest') == target and a.get('status') == 'admissible']
    if len(ok) >= min_quorum:
        return {'status': 'admissible', 'quorum_strength': len(ok), 'row_digest': target}
    return {'status': 'insufficient_witnesses', 'quorum_strength': len(ok), 'row_digest': target}
