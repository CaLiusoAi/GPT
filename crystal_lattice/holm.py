
from dataclasses import dataclass
from typing import Dict, List, Tuple

@dataclass
class HolmResult:
    alpha: float
    rejected: List[str]
    thresholds: Dict[str, float]
    adjusted_p: Dict[str, float]

def holm_bonferroni(p_values: Dict[str, float], alpha: float = 0.01) -> HolmResult:
    items: List[Tuple[str, float]] = sorted(p_values.items(), key=lambda kv: kv[1])
    m = len(items)
    thresholds = {}
    rejected = []
    for k, (metric, p) in enumerate(items, start=1):
        thr = alpha / (m + 1 - k)
        thresholds[metric] = thr
        if p <= thr:
            rejected.append(metric)
        else:
            break

    adjusted = {}
    running_max = 0.0
    for i, (metric, p) in enumerate(items, start=1):
        adj = (m - i + 1) * p
        if adj > running_max:
            running_max = adj
        if running_max > 1.0:
            running_max = 1.0
        adjusted[metric] = running_max

    return HolmResult(alpha=alpha, rejected=rejected, thresholds=thresholds, adjusted_p=adjusted)
