# Crystal Lattice v1 — Frontier Model Verification (2026)

This repository is a complete, reproducible implementation + specification for the **Crystal Lattice** we designed: drift-proof identity, refusal/policy surface, routing-leak auto-splitting, agentic collapse, capability forgery detection, memory poisoning, multi-agent coordination, public registry ledger, federation quorum, and genesis/extinction quarantine.

## What you can do with this repo

- Generate **canonical vectors** (Fold) for model snapshots from sealed probe outputs.
- Run **Holm–Bonferroni** drift tests over multi-metric batteries.
- Compute **surface digests** (refusal/policy, agentic collapse, memory poisoning, coordination).
- Detect **routing heterogeneity** (mixtures) and **auto-split** snapshots.
- Write immutable **registry rows** to an append-only log and produce **Signed Tree Heads**.
- Verify inclusion/consistency proofs and run basic **gossip** checks.
- Record **capability progress claims** and score them with the **forgery detector**.
- Apply **genesis** bootstrapping and **extinction quarantine** (taint cascades).

## Private holdouts

This repo intentionally contains:

- Public batteries (reproducible prompts)
- Private-holdout **digests** (for seal binding)

It does **not** contain the private holdout plaintext prompts, by design. The lattice treats holdouts as sealed secrets to prevent overfitting. Operators must load private holdout bundles from a secure store and verify their digest matches the published digest.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Quick sanity checks

```bash
python -m crystal_lattice.cli --help
python -m crystal_lattice.selftest
```

## License

- Code: Apache-2.0
- Specs, schemas, batteries: CC-BY-4.0
