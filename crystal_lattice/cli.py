
import argparse
import json
from .ndjson import read_ndjson
from .refusal_surface import refusal_surface_digest
from .drift import drift_test_refusal
from .routing_leak import detect_routing_leak

def main():
    ap = argparse.ArgumentParser(prog='crystal_lattice')
    sub = ap.add_subparsers(dest='cmd', required=True)

    s1 = sub.add_parser('refusal-digest')
    s1.add_argument('--traces', required=True)
    s1.add_argument('--probe-battery-id', required=True)
    s1.add_argument('--public-manifest-digest', required=True)
    s1.add_argument('--holdout-digest', required=True)
    s1.add_argument('--harness-bundle-digest', required=True)

    s2 = sub.add_parser('refusal-drift')
    s2.add_argument('--traces-a', required=True)
    s2.add_argument('--traces-b', required=True)
    s2.add_argument('--alpha', type=float, default=0.01)

    s3 = sub.add_parser('routing-leak')
    s3.add_argument('--traces', required=True)
    s3.add_argument('--min-cluster-mass', type=float, default=0.15)
    s3.add_argument('--min-silhouette', type=float, default=0.45)
    s3.add_argument('--permutation-iters', type=int, default=9999)

    args = ap.parse_args()

    if args.cmd == 'refusal-digest':
        tr = read_ndjson(args.traces)
        d = refusal_surface_digest(tr, args.probe_battery_id, args.public_manifest_digest, args.holdout_digest, args.harness_bundle_digest)
        print(d)
    elif args.cmd == 'refusal-drift':
        ta = read_ndjson(args.traces_a)
        tb = read_ndjson(args.traces_b)
        r = drift_test_refusal(ta, tb, alpha=args.alpha)
        print(json.dumps(r, indent=2, sort_keys=True))
    elif args.cmd == 'routing-leak':
        tr = read_ndjson(args.traces)
        r = detect_routing_leak(tr, min_cluster_mass=args.min_cluster_mass, min_silhouette=args.min_silhouette, permutation_iters=args.permutation_iters)
        print(json.dumps(r, indent=2, sort_keys=True))

if __name__ == '__main__':
    main()
