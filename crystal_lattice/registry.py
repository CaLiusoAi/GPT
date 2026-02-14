
    import json
    import time
    from typing import Dict, Any, List
    from .canonical import canonical_json_bytes
    from .digest import blake3_hex, sha3_256_hex
    from .merkle import merkle_root, inclusion_proof
    from .crypto import load_private_key_pem, sign_b64

    def row_digest_blake3(row_without_signatures: Dict[str, Any]) -> str:
        return blake3_hex(canonical_json_bytes(row_without_signatures))

    def append_row(ledger_path: str, row: Dict[str, Any], operator_privkey_pem: str) -> Dict[str, Any]:
        # Append-only NDJSON ledger; returns append proof
        priv = load_private_key_pem(operator_privkey_pem)
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())

        # Load previous digest (sha3 over entire previous line) for chaining
        prev_digest = '0'*64
        line_no = 0
        try:
            with open(ledger_path, 'r', encoding='utf-8') as f:
                for line_no, line in enumerate(f, start=1):
                    if line.strip():
                        prev_digest = sha3_256_hex(line.encode('utf-8'))
        except FileNotFoundError:
            line_no = 0

        row_no_sig = dict(row)
        row_no_sig.pop('signatures', None)

        rd = row_digest_blake3(row_no_sig)
        canonical_bytes = (prev_digest + rd + ts).encode('utf-8')
        sig = sign_b64(priv, canonical_bytes)

        append_proof = {
            'ndjson_line_number': line_no + 1,
            'previous_line_digest_sha3_256': prev_digest,
            'append_timestamp_utc': ts,
            'operator_sig_ed25519_b64': sig,
            'row_digest_blake3': rd
        }

        row['ledger_append_proof'] = append_proof

        with open(ledger_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(row, sort_keys=True, separators=(',',':')))
            f.write('
')

        return append_proof

    def compute_sth(ledger_path: str, operator_privkey_pem: str) -> Dict[str, Any]:
        priv = load_private_key_pem(operator_privkey_pem)
        leaves: List[bytes] = []
        with open(ledger_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                leaves.append(line.encode('utf-8'))
        root = merkle_root(leaves).hex()
        ts = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        sth_no_sig = {'tree_size': len(leaves), 'root_hash': root, 'timestamp_utc': ts}
        sig = sign_b64(priv, canonical_json_bytes(sth_no_sig))
        sth = dict(sth_no_sig)
        sth['operator_sig_ed25519_b64'] = sig
        return sth

    def compute_inclusion_proof(ledger_path: str, leaf_index: int) -> Dict[str, Any]:
        leaves: List[bytes] = []
        with open(ledger_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                leaves.append(line.encode('utf-8'))
        proof = inclusion_proof(leaves, leaf_index)
        return {'leaf_index': leaf_index, 'proof_hashes': [p.hex() for p in proof]}
