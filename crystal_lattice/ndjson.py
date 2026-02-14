
    import json
    from typing import Iterable, Dict, Any, List

    def read_ndjson(path: str) -> List[Dict[str, Any]]:
        out = []
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                out.append(json.loads(line))
        return out

    def write_ndjson(path: str, records: Iterable[Dict[str, Any]]):
        with open(path, 'w', encoding='utf-8') as f:
            for r in records:
                f.write(json.dumps(r, sort_keys=True, separators=(',',':')))
                f.write('
')
