"""Safe local artifact paths; report fields never select directories."""

import os
import tempfile
from pathlib import Path


def reject_symlink_path(path):
    path = Path(path).absolute()
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symlink path forbidden")


def atomic_text(path, content):
    path = Path(path)
    reject_symlink_path(path)
    fd, temporary = tempfile.mkstemp(prefix=".report-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
