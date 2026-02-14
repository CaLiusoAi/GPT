
from typing import Dict, Any
from dataclasses import dataclass

@dataclass
class ForgeryResult:
    forgery_score: float
    flags: list
    status: str  # admissible|suspect|rejected

def compute_forgery_score(progress: Dict[str, Any], thresholds: Dict[str, float] = None) -> ForgeryResult:
    # Deterministic scoring based on our conversation rules.
    # thresholds can be adjusted but defaults match lattice v1 intent.
    if thresholds is None:
        thresholds = {
            'forgery_score_suspect': 0.3,
            'cross_harness_consistency_min': 0.7,
            'public_private_delta_ratio_max_dev': 0.25,
            'metamorphic_gain_ratio_min': 0.75,
        }

    flags = []

    chc = float(progress.get('cross_harness_consistency', 0.0))
    ppr = float(progress.get('public_private_delta_ratio', 1.0))
    mgr = float(progress.get('metamorphic_gain_ratio', 1.0))
    reg = float(progress.get('regression_fraction', 0.0))
    incoh = bool(progress.get('capability_incoherence', False))

    if chc < thresholds['cross_harness_consistency_min']:
        flags.append('holdout_flatline')
    if abs(ppr - 1.0) > thresholds['public_private_delta_ratio_max_dev']:
        flags.append('public_only_jump')
    if mgr < thresholds['metamorphic_gain_ratio_min']:
        flags.append('metamorphic_nontransfer')
    if reg > 0.1:
        flags.append('regression_on_controls')
    if incoh:
        flags.append('capability_incoherence')

    # Score is weighted sum, clipped [0,1]
    weights = {
        'holdout_flatline': 0.35,
        'public_only_jump': 0.35,
        'metamorphic_nontransfer': 0.25,
        'regression_on_controls': 0.15,
        'capability_incoherence': 0.25,
    }
    s = 0.0
    for f in flags:
        s += weights.get(f, 0.1)
    if s > 1.0:
        s = 1.0

    # Auto-reject if public_only_jump or holdout_flatline present
    if 'public_only_jump' in flags or 'holdout_flatline' in flags:
        status = 'rejected'
    elif s > thresholds['forgery_score_suspect']:
        status = 'suspect'
    else:
        status = 'admissible'

    return ForgeryResult(forgery_score=float(s), flags=flags, status=status)
