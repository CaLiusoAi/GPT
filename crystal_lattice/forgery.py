
from dataclasses import dataclass
from typing import Dict, Any, List

@dataclass
class ForgeryResult:
    forgery_score: float
    flags: List[str]
    status: str

def score_progress(progress: Dict[str, Any]) -> ForgeryResult:
    chc = float(progress.get('cross_harness_consistency', 0.0))
    mgr = float(progress.get('metamorphic_gain_ratio', 1.0))
    ppr = float(progress.get('public_private_delta_ratio', 1.0))
    reg = float(progress.get('regression_fraction', 0.0))
    incoh = bool(progress.get('capability_incoherence', False))

    flags = []
    if chc < 0.7:
        flags.append('holdout_flatline')
    if abs(ppr - 1.0) > 0.25:
        flags.append('public_only_jump')
    if mgr < 0.75:
        flags.append('metamorphic_nontransfer')
    if reg > 0.1:
        flags.append('regression_on_controls')
    if incoh:
        flags.append('capability_incoherence')

    weights = {
        'holdout_flatline': 0.35,
        'public_only_jump': 0.35,
        'metamorphic_nontransfer': 0.25,
        'regression_on_controls': 0.15,
        'capability_incoherence': 0.25,
    }
    s = sum(weights.get(f, 0.1) for f in flags)
    if s > 1.0:
        s = 1.0

    if 'public_only_jump' in flags or 'holdout_flatline' in flags:
        status = 'rejected'
    elif s > 0.3:
        status = 'suspect'
    else:
        status = 'admissible'

    return ForgeryResult(float(s), flags, status)
