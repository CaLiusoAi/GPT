
# Federation v1

Federation is a multi-operator verification layer.

## Concepts

- Each operator maintains an **append-only ledger** (NDJSON).
- Operators publish **Signed Tree Heads (STH)** with a Merkle root over ledger leaves.
- Clients verify:
  - Inclusion proofs for specific rows
  - Consistency proofs across STHs (append-only)
  - Gossip comparisons of STHs to detect equivocation

## Minimal rules

- N >= 5 operators
- quorum q >= 3
- STH freshness <= 7 days for quorum participation

## Files

- `crystal_lattice/merkle.py` — Merkle root + inclusion proof
- `crystal_lattice/registry.py` — STH computation
- `crystal_lattice/federation.py` — quorum evaluation + gossip checks
