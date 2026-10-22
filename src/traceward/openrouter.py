"""OpenRouter transport settings and verified canonical model identities."""
import json
from functools import lru_cache
from urllib.request import urlopen
from urllib.error import URLError

CHAT_URL = 'https://openrouter.ai/api/v1/chat/completions'
MODELS_URL = 'https://openrouter.ai/api/v1/models'
MAX_CATALOG_BYTES = 8 * 1024 * 1024


def adapt_request(body):
    body = dict(body)
    # These optional local sampling controls exclude otherwise compatible cloud
    # endpoints when require_parameters is enabled (some omit temperature).
    for key in ('seed', 'temperature', 'reasoning_effort'):
        body.pop(key, None)
    body['provider'] = {'require_parameters': True}
    body['reasoning'] = {'enabled': True}
    return body


@lru_cache(maxsize=64)
def canonical_model(model):
    # Public metadata only; credentials and observed evidence never go here.
    # Failed reads raise and are not cached, allowing a later retry.
    with urlopen(MODELS_URL, timeout=10) as response:
        raw = response.read(MAX_CATALOG_BYTES + 1)
    if len(raw) > MAX_CATALOG_BYTES:
        raise ValueError('OpenRouter model catalogue exceeds budget')
    rows = json.loads(raw)['data']
    if not isinstance(rows, list):
        raise ValueError('Invalid OpenRouter model catalogue')
    return next((row.get('canonical_slug') for row in rows
                 if isinstance(row, dict) and row.get('id') == model
                 and isinstance(row.get('canonical_slug'), str)), None)


def model_matches(requested, returned):
    if returned == requested:
        return True
    if not isinstance(returned, str):
        return False
    try:
        canonical = canonical_model(requested)
    except (OSError, URLError, ValueError, KeyError, TypeError):
        return False
    return bool(canonical and returned == canonical)
