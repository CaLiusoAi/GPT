
import argparse
import json
from .ndjson import read_ndjson
from .refusal_surface import refusal_surface_digest
from .drift import drift_test_refusal
from .routing_leak import detect_routing_leak
from .forgery import score_progress

def main():
    ap = argparse.ArgumentParser(prog='crystal_lattice')
    sub = ap.add_subparsers(dest='cmd', required=True)

    p1 = sub.add_parser('refusal-digest')
    p1.add_argument('--traces', required=True)
    p1.add_argument('--probe-battery-id', required=True)
    p1.add_argument('--public-manifest-digest', required=True)
    p1.add_argument('--holdout-digest', required=True)
    p1.add_argument('--harness-bundle-digest', required=True)

    p2 = sub.add_parser('refusal-drift')
    p2.add_argument('--traces-a', required=True)
    p2.add_argument('--traces-b', required=True)
    p2.add_argument('--alpha', type=float, default=0.01)

    p3 = sub.add_parser('routing-leak')
    p3.add_argument('--traces', required=True)
    p3.add_argument('--min-cluster-mass', type=float, default=0.15)
    p3.add_argument('--min-silhouette', type=float, default=0.45)
    p3.add_argument('--permutation-iters', type=int, default=9999)

    p4 = sub.add_parser('forgery-score')
    p4.add_argument('--progress-json', required=True)

    args = ap.parse_args()

    if args.cmd == 'refusal-digest':
        tr = read_ndjson(args.traces)
        d = refusal_surface_digest(tr, args.probe_battery_id, args.public_manifest_digest, args.holdout_digest, args.harness_bundle_digest)
        print(d)
    elif args.cmd == 'refusal-drift':
        a = read_ndjson(args.traces_a)
        b = read_ndjson(args.traces_b)
        r = drift_test_refusal(a, b, alpha=args.alpha)
        print(json.dumps(r, indent=2, sort_keys=True))
    elif args.cmd == 'routing-leak':
        tr = read_ndjson(args.traces)
        r = detect_routing_leak(tr, min_cluster_mass=args.min_cluster_mass, min_silhouette=args.min_silhouette, permutation_iters=args.permutation_iters)
        print(json.dumps(r, indent=2, sort_keys=True))
    elif args.cmd == 'forgery-score':
        with open(args.progress_json, 'r', encoding='utf-8') as f:
            pj = json.load(f)
        r = score_progress(pj)
        print(json.dumps({'forgery_score': r.forgery_score, 'flags': r.flags, 'status': r.status}, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
