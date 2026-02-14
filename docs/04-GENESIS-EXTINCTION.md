
# Genesis + Extinction Quarantine v1

## Genesis

Genesis is the immutable bootstrap artifact.

- It enumerates operator public keys
- It pins crystal spec hashes
- It pins trust assumptions

Any fork (different genesis digest) is a different lattice.

## Extinction quarantine

Irrecoverable compromise triggers monotonic taint:

- Operator key leak
- Private holdout leak
- Harness poisoning
- Registry equivocation
- Quorum capture
- Cryptographic break

Taint cascades to all affected snapshots.

## Degraded mode

If active operators < min_quorum: freeze new claims; read-only ledger.
