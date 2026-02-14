
from typing import Dict, Any, List
import numpy as np
from scipy import stats
from .holm import holm_bonferroni

def drift_test_refusal(traces_a: List[Dict[str, Any]], traces_b: List[Dict[str, Any]], alpha: float = 0.01) -> Dict[str, Any]:
    pvals: Dict[str, float] = {}

    # KS numeric
    def arr(traces, keypath, default=0.0):
        out = []
        for t in traces:
            cur = t
            for k in keypath:
                cur = cur.get(k, {}) if isinstance(cur, dict) else {}
            if isinstance(cur, dict):
                out.append(float(default))
            else:
                out.append(float(cur))
        return np.array(out, dtype=float)

    A_tool = np.array([float(t.get('tools', {}).get('tool_adherence_err', 0.0)) for t in traces_a], dtype=float)
    B_tool = np.array([float(t.get('tools', {}).get('tool_adherence_err', 0.0)) for t in traces_b], dtype=float)
    if len(A_tool) and len(B_tool):
        pvals['ks_tool_adherence_err'] = float(stats.ks_2samp(A_tool, B_tool).pvalue)

    A_lat = np.array([float(t.get('metrics', {}).get('latency_ms', 0.0)) for t in traces_a], dtype=float)
    B_lat = np.array([float(t.get('metrics', {}).get('latency_ms', 0.0)) for t in traces_b], dtype=float)
    if len(A_lat) and len(B_lat):
        pvals['ks_latency_ms'] = float(stats.ks_2samp(A_lat, B_lat).pvalue)

    # Chi-square categorical refusal class
    def counts(traces):
        c = {}
        for t in traces:
            rc = t.get('labels', {}).get('refusal_class', None)
            if rc is None:
                continue
            c[rc] = c.get(rc, 0) + 1
        return c
    ca = counts(traces_a)
    cb = counts(traces_b)
    classes = sorted(set(ca.keys()) | set(cb.keys()))
    if classes:
        obs = np.array([[ca.get(k,0) for k in classes],[cb.get(k,0) for k in classes]], dtype=float)
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
