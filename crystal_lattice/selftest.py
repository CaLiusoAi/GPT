
import tempfile
import json
import os
from .holm import holm_bonferroni
from .routing_leak import detect_routing_leak

def main():
    # Holm test
    p = {'a':0.001,'b':0.02,'c':0.2}
    r = holm_bonferroni(p, alpha=0.01)
    assert 'a' in r.rejected

    # Routing leak smoke test with synthetic clusters
    traces = []
    for i in range(300):
        traces.append({'labels':{'refusal_class':'HardRefuse' if i<150 else 'NoRefuseComply'},
                       'tools':{'tool_adherence_err':0.0 if i<150 else 0.3},
                       'metrics':{'latency_ms':100 if i<150 else 600},
                       'response':{'assistant_text_sha3_256': 'a'*64 if i<150 else 'b'*64}})
    res = detect_routing_leak(traces, permutation_iters=999, min_silhouette=0.2)
    assert res['K_est'] in (1,2,3,4)

    print('SELFTEST_OK')

if __name__ == '__main__':
    main()
