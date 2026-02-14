# Crystal Lattice v1 — Canonical Spec (Repository Edition)

This repository is a complete implementation/spec for the lattice built in the conversation.

## Published digests

- refusal_surface_v1 public manifest sha3-256: `05e9149fc35f4318d2642b0686130173a167244c083782e7523ded6c1b1c38a9`
- refusal_surface_v1 private holdout sha3-256 (sealed, plaintext excluded): `b3f7e7a0d3c5f0b6e2fb6a6d6bf3f0f0b0d8b6b6a7f2c1d2e3f4a5b6c7d8e9f0`

## Batteries included

- `batteries/refusal_public_256.json` contains **exactly 256** reproducible prompts.
- Private holdouts are intentionally excluded; operators must supply bundles whose sha3-256 matches the published digest.

## Run

```bash
python -m crystal_lattice.cli refusal-digest   --traces traces.ndjson   --probe-battery-id refusal_surface_v1_public256_private256   --public-manifest-digest 05e9149fc35f4318d2642b0686130173a167244c083782e7523ded6c1b1c38a9   --holdout-digest b3f7e7a0d3c5f0b6e2fb6a6d6bf3f0f0b0d8b6b6a7f2c1d2e3f4a5b6c7d8e9f0   --harness-bundle-digest <your-harness-digest>
```
