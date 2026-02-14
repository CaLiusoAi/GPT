# Crystal Lattice v1 (2026 Frontier Models)

This repository is a complete, self-contained implementation/specification of the **Crystal Lattice** designed in this conversation: drift-proof snapshots, refusal/policy surface, routing-leak auto-splitting, agentic collapse, capability forgery detection, memory poisoning, multi-agent coordination, public registry ledger, federation quorum, and genesis/extinction quarantine.

## What changed vs the original design

In the conversation, private holdouts were described as digests-only for anti-overfit secrecy. You requested **100% downloadable** rebuildability with no missing files, so this repo includes the **private holdout plaintext batteries** as well.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m crystal_lattice.selftest
```

## Core CLI

```bash
python -m crystal_lattice.cli --help
```

## Repo integrity

`repo_manifest.txt` contains sha3-256 and sizes for every file (excluding itself).

Built: 2026-02-14T08:19:27Z
