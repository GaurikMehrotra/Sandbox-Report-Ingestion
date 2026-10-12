"""Bounded JSON-only input. No report-derived code or network operations."""

import hashlib
import json
import math
import os
import stat
from pathlib import Path

from .files import reject_symlink_path

MAX_BYTES = 16 * 1024 * 1024
MAX_NODES = 100_000
MAX_DEPTH = 40


class InputError(ValueError):
    pass


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("duplicate JSON object key")
        result[key] = value
    return result


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise InputError("nonfinite number")
    return number


def decode(raw: bytes, max_bytes=MAX_BYTES):
    if len(raw) > max_bytes:
        raise InputError("report exceeds configured byte limit")
    try:
        data = json.loads(
            raw.decode("utf-8-sig"),
            object_pairs_hook=_pairs,
            parse_float=finite_float,
            parse_constant=lambda _: (_ for _ in ()).throw(InputError("nonfinite number")),
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise InputError("invalid UTF-8 JSON: " + type(exc).__name__) from exc
    if not isinstance(data, dict):
        raise InputError("report root must be an object")
    stack = [(data, 0)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise InputError("JSON complexity limit exceeded")
        children = (
            value.values() if isinstance(value, dict) else value if isinstance(value, list) else []
        )
        stack.extend((child, depth + 1) for child in children)
    return data


def read_report(path: Path, max_bytes=MAX_BYTES):
    if path.suffix.lower() != ".json":
        raise InputError("only .json files are supported")
    # O_NOFOLLOW also closes the symlink replacement race on platforms supporting it.
    reject_symlink_path(path)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise InputError("input must be a regular file")
        raw = stream.read(max_bytes + 1)
    return raw, decode(raw, max_bytes), hashlib.sha256(raw).hexdigest()
