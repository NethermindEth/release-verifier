"""Check results, finding classification, reports and exit codes."""

from __future__ import annotations

import datetime as _dt
import enum
import json
from dataclasses import dataclass, field
from typing import Any

EXIT_OK = 0
EXIT_COMPROMISE = 1
EXIT_TOOL_ERROR = 2


class Status(str, enum.Enum):
    """Outcome of one check.

    Only FAIL (compromise-class) and ERROR (tool/infra) affect the exit code.
    """

    PASS = "pass"
    INFO = "info"
    LEGACY = "legacy"  # expected gap for releases made before the project adopted the control
    SKIPPED = "skipped"  # not applicable or deliberately not run
    WARN = "warn"  # needs human attention, not evidence of compromise on its own
    FAIL = "fail"  # compromise-class: evidence that a release artifact or pointer was tampered with
    ERROR = "error"  # the tool or a dependency failed, so the check is inconclusive

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Status.PASS: 0,
    Status.SKIPPED: 1,
    Status.INFO: 2,
    Status.LEGACY: 3,
    Status.WARN: 4,
    Status.ERROR: 5,
    Status.FAIL: 6,
}


@dataclass
class Result:
    check: str
    status: Status
    subject: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        out = {
            "check": self.check,
            "status": self.status.value,
            "subject": self.subject,
            "message": self.message,
        }
        if self.details:
            out["details"] = self.details
        return out

    @property
    def is_finding(self) -> bool:
        return self.status is not Status.PASS


def exit_code(results: list[Result]) -> int:
    """1 if any compromise-class finding, else 2 if any tool error, else 0."""
    statuses = {r.status for r in results}
    if Status.FAIL in statuses:
        return EXIT_COMPROMISE
    if Status.ERROR in statuses:
        return EXIT_TOOL_ERROR
    return EXIT_OK


def utc_now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class Report:
    command: str
    project: str
    target: str | None = None
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    results: list[Result] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def add(self, check: str, status: Status, subject: str, message: str, **details: Any) -> Result:
        r = Result(check, status, subject, message, {k: v for k, v in details.items() if v is not None})
        self.results.append(r)
        return r

    def extend(self, results: list[Result]) -> None:
        self.results.extend(results)

    @property
    def exit_code(self) -> int:
        return exit_code(self.results)

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Status}
        for r in self.results:
            c[r.status.value] += 1
        return c

    def to_json(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "command": self.command,
            "project": self.project,
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "exit_code": self.exit_code,
            "counts": self.counts(),
            "meta": self.meta,
            "results": [r.to_json() for r in self.results],
        }

    def dumps(self) -> str:
        return json.dumps(self.to_json(), indent=2, sort_keys=False)

    def summary(self, verbose: bool = False) -> str:
        """Human summary: findings ordered by severity; passes only listed when verbose."""
        verdict = {
            EXIT_OK: "OK",
            EXIT_COMPROMISE: "COMPROMISE-CLASS FINDINGS",
            EXIT_TOOL_ERROR: "INCONCLUSIVE (tool/infra errors)",
        }[self.exit_code]
        title = f"{self.command} {self.project}" + (f" {self.target}" if self.target else "")
        lines = [f"== release-verifier {title}: {verdict} (exit {self.exit_code})"]
        counts = ", ".join(f"{k}={v}" for k, v in self.counts().items() if v)
        lines.append(f"   {counts}")
        shown = sorted(
            (r for r in self.results if verbose or r.is_finding),
            key=lambda r: -r.status.rank,
        )
        for r in shown:
            lines.append(f"[{r.status.value.upper():7}] {r.check} {r.subject}: {r.message}")
        return "\n".join(lines)
