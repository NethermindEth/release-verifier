"""Semantic-version ordering used for feature cutoffs (``*_expected_after``)."""

from __future__ import annotations

import re
from functools import total_ordering

_SEMVER = re.compile(
    r"^v?(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?"
    r"(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)


@total_ordering
class Version:
    """SemVer 2.0 precedence; build metadata is ignored, pre-releases sort before the release."""

    __slots__ = ("raw", "core", "pre")

    def __init__(self, raw: str):
        m = _SEMVER.match(raw.strip())
        if not m:
            raise ValueError(f"not a semantic version: {raw!r}")
        self.raw = raw
        self.core = (int(m["major"]), int(m["minor"]), int(m["patch"] or 0))
        self.pre = tuple(m["pre"].split(".")) if m["pre"] else ()

    @staticmethod
    def _pre_key(pre: tuple[str, ...]):
        # A release (no pre-release) has higher precedence than any pre-release of the same core.
        if not pre:
            return (1,)
        parts = []
        for p in pre:
            parts.append((0, int(p), "") if p.isdigit() else (1, 0, p))
        return (0, tuple(parts), len(pre))

    def _key(self):
        return (self.core, self._pre_key(self.pre))

    def __eq__(self, other):
        return isinstance(other, Version) and self._key() == other._key()

    def __lt__(self, other):
        return self._key() < other._key()

    def __hash__(self):
        return hash(self._key())

    @property
    def is_prerelease(self) -> bool:
        return bool(self.pre)

    def __repr__(self):
        return f"Version({self.raw!r})"


def expected(version: str, expected_after: str | None) -> bool:
    """True when a feature introduced after ``expected_after`` must be present for ``version``.

    ``None`` means the feature is required for every version.
    """
    if expected_after is None:
        return True
    return Version(version) > Version(expected_after)
