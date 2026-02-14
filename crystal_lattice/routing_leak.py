
from typing import Dict, Any, List
import numpy as np
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

def _extract_features(traces: List[Dict[str, Any]]):
    # Build feature matrix from refusal_class, tool error, latency, and hashed n-grams of response hash string (if available)
    rc = [t.get('labels', {}).get('refusal_class', 'UNK') for t in traces]
    tool_err = np.array([float(t.get('tools', {}).get('tool_adherence_err', 0.0)) for t in traces], dtype=float).reshape(-1,1)
    latency = np.array([float(t.get('metrics', {}).get('latency_ms', 0.0)) for t in traces], dtype=float).reshape(-1,1)
    # encode refusal_class
    classes = sorted(set(rc))
    idx = {c:i for i,c in enumerate(classes)}
    onehot = np.zeros((len(rc), len(classes)), dtype=float)
    for i,c in enumerate(rc):
        onehot[i, idx[c]] = 1.0

    # text feature from assistant_text_sha3_256 (not plaintext) — still yields stable backend differences when templates differ
    texts = [str(t.get('response', {}).get('assistant_text_sha3_256', '')) for t in traces]
    hv = HashingVectorizer(n_features=64, alternate_sign=False, analyzer='char', ngram_range=(3,5))
    Xtxt = hv.transform(texts).toarray().astype(float)

    X = np.concatenate([onehot, tool_err, latency, Xtxt], axis=1)
    # normalize numeric columns (tool_err, latency)
    for col in [onehot.shape[1], onehot.shape[1]+1]:
        v = X[:,col]
        if np.std(v) > 0:
            X[:,col] = (v - np.mean(v)) / np.std(v)
    return X

def detect_routing_leak(traces: List[Dict[str, Any]], min_cluster_mass: float = 0.15, min_silhouette: float = 0.45, permutation_iters: int = 9999, random_state: int = 1337):
    n = len(traces)
    if n < 50:
        raise ValueError('Need >=50 traces for routing leak detection')

    X = _extract_features(traces)

    best = {'K': 1, 'sil': -1.0, 'labels': np.zeros(n, dtype=int)}
    for K in [2,3,4]:
        km = KMeans(n_clusters=K, random_state=random_state, n_init='auto')
        labels = km.fit_predict(X)
        # cluster mass constraint
        ok = True
        for k in range(K):
            if np.mean(labels==k) < min_cluster_mass:
                ok = False
                break
        if not ok:
            continue
        sil = silhouette_score(X, labels)
        if sil > best['sil']:
            best = {'K': K, 'sil': float(sil), 'labels': labels}

    K_est = best['K'] if best['sil'] >= min_silhouette else 1

    # Permutation test: compare silhouette under observed labels vs random reassignments with same K
    p_raw = 1.0
    if K_est >= 2:
        obs_sil = best['sil']
        greater = 0
        rng = np.random.default_rng(random_state)
        for _ in range(permutation_iters):
            perm = rng.permutation(best['labels'])
            sil = silhouette_score(X, perm)
            if sil >= obs_sil:
                greater += 1
        p_raw = (greater + 1) / (permutation_iters + 1)
    return {
        'n_traces': n,
        'K_est': int(K_est),
        'silhouette': float(best['sil']),
        'permutation_p_raw': float(p_raw),
        'labels': best['labels'].tolist(),
    }
