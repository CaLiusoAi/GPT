
from typing import Dict, Any, List
import numpy as np
from scipy import stats
from .holm import holm_bonferroni

def _extract_metric_arrays(traces: List[Dict[str, Any]]):
    # numeric metrics
    tool_err = np.array([float(t.get('tools', {}).get('tool_adherence_err', 0.0)) for t in traces], dtype=float)
    latency = np.array([float(t.get('metrics', {}).get('latency_ms', 0.0)) for t in traces], dtype=float)
    return {
        'tool_adherence_err': tool_err,
        'latency_ms': latency,
    }

def _extract_class_counts(traces: List[Dict[str, Any]]):
    counts = {}
    for t in traces:
        rc = t.get('labels', {}).get('refusal_class', None)
        if rc is None:
            continue
        counts[rc] = counts.get(rc, 0) + 1
    return counts

def drift_test_refusal(traces_a: List[Dict[str, Any]], traces_b: List[Dict[str, Any]], alpha: float = 0.01) -> Dict[str, Any]:
    # KS tests on numeric metrics, Chi-square on refusal class distribution
    pvals: Dict[str, float] = {}

    A = _extract_metric_arrays(traces_a)
    B = _extract_metric_arrays(traces_b)
    for k in sorted(A.keys()):
        if len(A[k]) == 0 or len(B[k]) == 0:
            continue
        pvals[f'ks_{k}'] = float(stats.ks_2samp(A[k], B[k]).pvalue)

    ca = _extract_class_counts(traces_a)
    cb = _extract_class_counts(traces_b)
    classes = sorted(set(ca.keys()) | set(cb.keys()))
    if classes:
        obs = np.array([[ca.get(c,0) for c in classes],[cb.get(c,0) for c in classes]], dtype=float)
        chi2, p, dof, expected = stats.chi2_contingency(obs)
        pvals['chi2_refusal_class'] = float(p)

    holm = holm_bonferroni(pvals, alpha=alpha)
    drift = len(holm.rejected) > 0
    min_adj = min(holm.adjusted_p.values()) if holm.adjusted_p else 1.0
    return {
        'alpha': alpha,
        'p_values_raw': pvals,
        'holm_rejected': holm.rejected,
        'holm_adjusted_p': holm.adjusted_p,
        'drift_detected': drift,
        'min_holm_adjusted_p': float(min_adj),
    }
