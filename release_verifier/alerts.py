"""Optional alert sinks configured through environment variables.

RELEASE_VERIFIER_SLACK_WEBHOOK     Slack incoming-webhook URL
RELEASE_VERIFIER_WEBHOOK_URL       generic endpoint; receives the full JSON report via POST
RELEASE_VERIFIER_WEBHOOK_TOKEN     optional bearer token for the generic webhook
RELEASE_VERIFIER_ALERT_ON          comma-separated statuses that trigger alerts (default: fail,error,warn)
RELEASE_VERIFIER_ALERT_REPEAT_HOURS  re-send an identical finding after this many hours (default: 24)

Webhook URLs and tokens are secrets: they are never logged or written to reports.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

from . import net
from .results import Report, Result, Status

log = logging.getLogger(__name__)
MAX_LINES = 25


def _alert_statuses() -> set[Status]:
    raw = os.environ.get("RELEASE_VERIFIER_ALERT_ON", "fail,error,warn")
    return {Status(s.strip()) for s in raw.split(",") if s.strip()}


def finding_key(project: str, r: Result) -> str:
    return hashlib.sha256(f"{project}|{r.check}|{r.status.value}|{r.subject}|{r.message}".encode()).hexdigest()[:32]


def select_new(report: Report, sent: dict[str, float], now: float, repeat_hours: float) -> list[Result]:
    """Findings that should be alerted: matching statuses, not already sent within the repeat window."""
    wanted = _alert_statuses()
    out = []
    for r in report.results:
        if r.status not in wanted:
            continue
        last = sent.get(finding_key(report.project, r))
        if last is None or now - last >= repeat_hours * 3600:
            out.append(r)
    return out


def slack_payload(report: Report, findings: list[Result]) -> dict[str, Any]:
    head = report.summary().splitlines()[0].lstrip("= ")
    lines = [f"*{head}*"]
    for r in sorted(findings, key=lambda r: -r.status.rank)[:MAX_LINES]:
        lines.append(f"• `{r.status.value}` {r.check} `{r.subject}`: {r.message}")
    if len(findings) > MAX_LINES:
        lines.append(f"… and {len(findings) - MAX_LINES} more (see the JSON report)")
    return {"text": "\n".join(lines)}


def dispatch(report: Report, state_dir: Path) -> bool:
    """Send alerts for new findings; returns False if a configured sink failed."""
    slack = os.environ.get("RELEASE_VERIFIER_SLACK_WEBHOOK")
    hook = os.environ.get("RELEASE_VERIFIER_WEBHOOK_URL")
    if not slack and not hook:
        return True
    sent_file = state_dir / "alerts-sent.json"
    sent: dict[str, float] = json.loads(sent_file.read_text()) if sent_file.is_file() else {}
    now = time.time()
    findings = select_new(report, sent, now, float(os.environ.get("RELEASE_VERIFIER_ALERT_REPEAT_HOURS", "24")))
    if not findings:
        return True
    ok = True
    if slack:
        try:
            net.post_json(slack, slack_payload(report, findings))
        except net.HttpError as e:
            log.error("Slack alert failed: HTTP %s", e.status)
            ok = False
    if hook:
        headers = {}
        if tok := os.environ.get("RELEASE_VERIFIER_WEBHOOK_TOKEN"):
            headers["Authorization"] = f"Bearer {tok}"
        try:
            net.post_json(hook, {"new_findings": [r.to_json() for r in findings], "report": report.to_json()}, headers)
        except net.HttpError as e:
            log.error("webhook alert failed: HTTP %s", e.status)
            ok = False
    if ok:
        for r in findings:
            sent[finding_key(report.project, r)] = now
        # Forget entries older than a week so the file stays small.
        sent = {k: v for k, v in sent.items() if now - v < 7 * 86400}
        sent_file.write_text(json.dumps(sent, indent=1))
    return ok
