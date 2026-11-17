"""Persistent state: watch snapshots, verified-release records, reports and caches.

Layout under ``<state>/<project>/``::

    snapshot.json            latest watch snapshot (the diff baseline)
    snapshots/<ts>.json      snapshot history (pruned to ``HISTORY``)
    verified.json            {tag: verification record}, written by `verify`
    reports/<cmd>-<ts>.json  every report
    cache/                   content-addressed caches (keys, manifests, downloads)
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

HISTORY = 200


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def _stamp(ts: str) -> str:
    return ts.replace(":", "").replace("-", "")


class State:
    def __init__(self, root: Path, project: str):
        self.dir = root / project
        self.dir.mkdir(parents=True, exist_ok=True)

    @property
    def cache_dir(self) -> Path:
        return self.dir / "cache"

    def _read(self, name: str) -> Any | None:
        p = self.dir / name
        return json.loads(p.read_text()) if p.is_file() else None

    def load_snapshot(self) -> dict[str, Any] | None:
        return self._read("snapshot.json")

    def save_snapshot(self, snap: dict[str, Any], advance: bool = True) -> None:
        """Store a snapshot in history; only ``advance`` makes it the baseline for the next diff."""
        text = json.dumps(snap, indent=2, sort_keys=True)
        _atomic_write(self.dir / "snapshots" / f"{_stamp(snap['taken_at'])}.json", text)
        if advance:
            _atomic_write(self.dir / "snapshot.json", text)
        history = sorted((self.dir / "snapshots").glob("*.json"))
        for old in history[:-HISTORY]:
            old.unlink()

    def load_verified(self) -> dict[str, Any]:
        return self._read("verified.json") or {}

    def record_verified(self, tag: str, record: dict[str, Any]) -> None:
        data = self.load_verified()
        data[tag] = record
        _atomic_write(self.dir / "verified.json", json.dumps(data, indent=2, sort_keys=True))

    def save_report(self, report: dict[str, Any]) -> Path:
        name = f"{report['command']}-{report['target'] + '-' if report.get('target') else ''}{_stamp(report['started_at'])}.json"
        path = self.dir / "reports" / name
        _atomic_write(path, json.dumps(report, indent=2))
        return path
