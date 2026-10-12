"""Conservative credential-field redaction for exports and LLM payloads."""

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential)"
)


def redact(value):
    if isinstance(value, dict):
        return {k: "[REDACTED]" if SENSITIVE.search(k) else redact(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        if value.lower().startswith(("http://", "https://")):
            try:
                p = urlsplit(value)
                netloc = p.netloc.split("@")[-1]
                query = urlencode(
                    [
                        (k, "[REDACTED]" if SENSITIVE.search(k) else v)
                        for k, v in parse_qsl(p.query, keep_blank_values=True)
                    ]
                )
                return urlunsplit((p.scheme, netloc, p.path, query, p.fragment))
            except ValueError:
                return "[INVALID URL]"
        value = re.sub(
            r"(?i)\b(password|token|api_key|secret)\s*[=:]\s*[^\s;,]+", r"\1=[REDACTED]", value
        )
        value = re.sub(r"(?i)\bBearer\s+[^\s;,]+", "Bearer [REDACTED]", value)
    return value
