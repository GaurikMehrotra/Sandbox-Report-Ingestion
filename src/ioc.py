"""Context-driven indicator extraction; validity is never a maliciousness verdict."""

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

from .models import IOC


def normalize(kind, value):
    if not isinstance(value, str) or not value or len(value) > 8192:
        return None
    v = value.strip()
    if kind in {"md5", "sha1", "sha256"}:
        return (
            v.lower()
            if re.fullmatch(
                r"[a-fA-F0-9]{" + str({"md5": 32, "sha1": 40, "sha256": 64}[kind]) + "}", v
            )
            else None
        )
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None
    if kind == "domain":
        try:
            v = v.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            return None
        if len(v) > 253 or "." not in v or normalize("ip", v):
            return None
        return (
            v
            if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in v.split("."))
            else None
        )
    if kind == "url":
        if any(c.isspace() or ord(c) < 32 for c in v):
            return None
        try:
            p = urlsplit(v)
            if (
                p.scheme.lower() not in {"http", "https"}
                or not p.hostname
                or p.username
                or p.password
            ):
                return None
            host = normalize("ip", p.hostname) or normalize("domain", p.hostname)
            if not host:
                return None
            netloc = "[" + host + "]" if ":" in host else host
            if p.port:
                netloc += ":" + str(p.port)
            return urlunsplit((p.scheme.lower(), netloc, p.path, p.query, p.fragment))
        except ValueError:
            return None
    if kind == "email":
        if v.count("@") != 1:
            return None
        local, domain = v.split("@")
        d = normalize("domain", domain)
        return (
            local + "@" + d
            if d and re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+", local)
            else None
        )
    if kind in {"file_path", "registry_path", "mutex", "filename", "process_name"}:
        v = value
        if any(ord(c) < 32 for c in v):
            return None
        # Do not resolve '.', '..', aliases, or case: the target OS may differ.
        return v.replace("/", "\\") if kind == "registry_path" else v
    return None


KEY_TYPES = {
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "ip": "ip",
    "dst": "ip",
    "src": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "uri": "url",
    "email": "email",
    "mutex": "mutex",
    "process_name": "process_name",
    "name": "filename",
}


def extract(evidence, report_id, include_nonpublic=True):
    result = {}
    for e in evidence:
        candidates = []

        def walk(v, key="", evidence_type=e.evidence_type, output=candidates):
            if isinstance(v, dict):
                for k, child in v.items():
                    walk(child, k.lower())
            elif isinstance(v, list):
                for child in v:
                    walk(child, key)
            elif isinstance(v, str):
                kind = KEY_TYPES.get(key)
                if kind == "filename" and evidence_type not in {"sample", "file"}:
                    kind = None
                if key in {"path", "file", "filepath"}:
                    kind = "registry_path" if evidence_type == "registry" else "file_path"
                if kind:
                    output.append((kind, v))

        walk(e.raw_value if isinstance(e.raw_value, (dict, list)) else e.normalized_value)
        if isinstance(e.normalized_value, str):
            kind = {
                "file": "file_path",
                "registry": "registry_path",
                "mutex": "mutex",
                "dns": "domain",
            }.get(e.evidence_type)
            if kind:
                candidates.append((kind, e.normalized_value))
        for kind, raw in candidates:
            value = normalize(kind, raw)
            if value is None:
                continue
            public = ipaddress.ip_address(value).is_global if kind == "ip" else None
            if public is False and not include_nonpublic:
                continue
            k = (kind, value)
            if k not in result:
                result[k] = IOC(
                    type=kind,
                    value=value,
                    original_values=[],
                    evidence_ids=[],
                    report_ids=[report_id],
                    public_ip=public,
                )
            item = result[k]
            if raw not in item.original_values:
                item.original_values.append(raw)
            if e.evidence_id not in item.evidence_ids:
                item.evidence_ids.append(e.evidence_id)
            if e.timestamp:
                item.first_seen = min(item.first_seen or e.timestamp, e.timestamp)
                item.last_seen = max(item.last_seen or e.timestamp, e.timestamp)
    return sorted(result.values(), key=lambda i: (i.type, i.value))
