
import math
import orjson
import numpy as np

ROUND_DECIMALS = 8

def round_float(x: float) -> float:
    if x is None:
        return x
    if isinstance(x, (int,)):
        return float(x)
    if isinstance(x, (float,)):
        if math.isnan(x) or math.isinf(x):
            raise ValueError('Non-finite float not allowed in canonical objects')
        return float(np.round(x, ROUND_DECIMALS))
    raise TypeError(f'Expected float/int/None, got {type(x)}')

def canonicalize(obj):
    # Recursively round floats and sort dict keys.
    if isinstance(obj, dict):
        return {k: canonicalize(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [canonicalize(x) for x in obj]
    if isinstance(obj, tuple):
        return [canonicalize(x) for x in obj]
    if isinstance(obj, float) or isinstance(obj, int):
        return round_float(obj)
    if obj is None or isinstance(obj, (str, bool)):
        return obj
    raise TypeError(f'Unsupported type for canonicalize: {type(obj)}')

def canonical_json_bytes(obj) -> bytes:
    c = canonicalize(obj)
    return orjson.dumps(c, option=orjson.OPT_SORT_KEYS)
