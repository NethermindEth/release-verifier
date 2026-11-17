"""SHA256SUMS parsing and file hashing."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

_LINE = re.compile(r"^(?P<hash>[0-9a-fA-F]{64}) (?P<mode>[ *])(?P<name>.+)$")


class ChecksumsError(ValueError):
    pass


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse GNU ``sha256sum`` output into ``{file name: lowercase hex}``.

    Strict: malformed lines, path components and duplicate names are rejected, because a lenient
    parser would let a tampered file smuggle in alternative entries.
    """
    out: dict[str, str] = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = _LINE.match(line)
        if not m:
            raise ChecksumsError(f"line {n}: not in sha256sum format: {line[:80]!r}")
        name = m["name"]
        if name.startswith("./"):
            name = name[2:]
        if "/" in name or "\\" in name or name in (".", ".."):
            raise ChecksumsError(f"line {n}: unexpected path in file name {name!r}")
        if name in out:
            raise ChecksumsError(f"line {n}: duplicate entry for {name!r}")
        out[name] = m["hash"].lower()
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def strip_algo(digest: str | None) -> str | None:
    """``sha256:<hex>`` -> ``<hex>``; other algorithms return None."""
    if not digest:
        return None
    algo, _, value = digest.partition(":")
    return value.lower() if algo == "sha256" and value else None
