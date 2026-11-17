"""Verification coverage: what one `verify` run established per artifact, and whether that is
enough for `watch` to treat the release as verified.

A record's ``coverage`` is ``{"source", "packages", "images", "extras", "channels"}``; every package
platform and image (``<repo>:<tag>@<platform>``) the project expects is listed, with ``absent``
for what the release does not publish, and every allowed extra asset the release publishes. Exit
code 0 only means "no compromise-class finding"; ``trusted`` additionally needs authenticated
source, every published package and image rebuilt and matching, and every extra asset signed and
checksummed (extras are not rebuilt).
"""

from __future__ import annotations

from typing import Any

AUTHENTICATED_SOURCES = ("signed", "pinned")
# Byte-identical zip, or (legacy releases only, recorded by `verify` at or below
# package_rebuild.reproducible_archives_expected_after) every entry identical.
PACKAGE_MATCH = ("identical", "contents-match")
IMAGE_MATCH = ("identical",)  # config digest equal
# Allowed extra assets (assets.extra_allowed) are never rebuilt; they count only when signed by the
# release key and listed in the signed checksums file.
EXTRA_OK = "signed-not-rebuilt"
ABSENT = "absent"
LIST_LIMIT = 3


def _group(kind: str, items: dict[str, str], ok: tuple[str, ...]) -> list[str]:
    by_status: dict[str, list[str]] = {}
    for name, status in sorted(items.items()):
        if status not in ok and status != ABSENT:
            by_status.setdefault(status, []).append(name)
    out = []
    for status, names in sorted(by_status.items()):
        more = f" (+{len(names) - LIST_LIMIT} more)" if len(names) > LIST_LIMIT else ""
        out.append(f"{kind} {status}: {', '.join(names[:LIST_LIMIT])}{more}")
    return out


def gaps(record: dict[str, Any]) -> list[str]:
    """Why a verification record does not establish trust; empty when it does."""
    if record.get("outcome") != "pass":
        return [f"verification outcome is {record.get('outcome')}"]
    cov = record.get("coverage")
    if not cov:
        return ["the record predates coverage tracking (re-run verify)"]
    out = []
    if cov.get("source") not in AUTHENTICATED_SOURCES:
        out.append(f"source {cov.get('source')}")
    out += _group("packages", cov.get("packages") or {}, PACKAGE_MATCH)
    out += _group("images", cov.get("images") or {}, IMAGE_MATCH)
    out += _group("extra assets", cov.get("extras") or {}, (EXTRA_OK,))
    return out


def trusted(record: dict[str, Any]) -> bool:
    return not gaps(record)
