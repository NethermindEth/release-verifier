"""GitHub artifact attestations (Sigstore) via ``gh attestation verify`` with explicitly fetched bundles.

Bundles are fetched over plain HTTPS so no GitHub login is needed; ``gh`` then verifies them
offline against the Sigstore public-good trust root and the expected signer workflow.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import github


@dataclass
class AttestationCheck:
    outcome: str  # verified | missing | failed | unavailable
    message: str
    details: dict[str, Any] = field(default_factory=dict)


def gh_available() -> bool:
    return shutil.which("gh") is not None


def verify_provenance(
    repo: str,
    subject: str,
    digest: str,
    signer_workflow: str,
    predicate_type: str,
    work_dir: Path,
) -> AttestationCheck:
    """Verify provenance for ``subject`` (a file path or ``oci://...@digest``) whose digest is ``digest``."""
    bundles = github.attestation_bundles(repo, digest)
    types = sorted({github.bundle_predicate_type(b) or "?" for b in bundles})
    matching = [b for b in bundles if github.bundle_predicate_type(b) == predicate_type]
    if not matching:
        return AttestationCheck("missing", f"no {predicate_type} attestation for {digest}", {"other_predicate_types": types})
    if not gh_available():
        return AttestationCheck("unavailable", "gh CLI not installed; cannot verify attestation bundles")
    work_dir.mkdir(parents=True, exist_ok=True)
    bundle_file = work_dir / f"{digest.replace(':', '_')}.jsonl"
    bundle_file.write_text("".join(json.dumps(b) + "\n" for b in matching))
    cmd = [
        "gh", "attestation", "verify", subject,
        "--bundle", str(bundle_file),
        "-R", repo,
        "--signer-workflow", signer_workflow,
        "--predicate-type", predicate_type,
        "--format", "json",
    ]
    p = subprocess.run(cmd, capture_output=True, env={**os.environ, "GH_PROMPT_DISABLED": "1"})
    if p.returncode == 0:
        details: dict[str, Any] = {"bundles": len(matching)}
        try:
            res = json.loads(p.stdout)
            details["source_ref"] = res[0]["verificationResult"]["signature"]["certificate"].get("sourceRepositoryRef")
            details["run"] = res[0]["verificationResult"]["signature"]["certificate"].get("runInvocationURI")
        except (ValueError, KeyError, IndexError, TypeError):
            pass
        return AttestationCheck("verified", f"provenance verified (signer {signer_workflow})", details)
    return AttestationCheck("failed", "gh attestation verify rejected the bundle", {"stderr": p.stderr.decode(errors="replace")[-1500:]})


def gh_authenticated() -> bool:
    if not gh_available():
        return False
    if os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN"):
        return True
    return subprocess.run(["gh", "auth", "status"], capture_output=True).returncode == 0


def release_attestation(repo: str, tag: str) -> dict[str, Any] | None:
    """The verified statement of GitHub's immutable-release attestation, or None if not available.

    Requires gh authentication (``gh release verify`` uses the API). Raises RuntimeError when gh
    reports a verification failure.
    """
    env = dict(os.environ)
    if not env.get("GH_TOKEN") and env.get("GITHUB_TOKEN"):
        env["GH_TOKEN"] = env["GITHUB_TOKEN"]
    p = subprocess.run(["gh", "release", "verify", tag, "-R", repo, "--format", "json"], capture_output=True, env=env)
    if p.returncode != 0:
        err = p.stderr.decode(errors="replace").strip()
        if "no attestation" in err.lower() or "not found" in err.lower():
            return None
        raise RuntimeError(err[-1000:])
    return json.loads(p.stdout)["verificationResult"]["statement"]


def release_attestation_subjects(statement: dict[str, Any]) -> tuple[str | None, dict[str, str]]:
    """``(commit sha1, {asset name: sha256})`` from a release attestation statement."""
    commit = None
    assets: dict[str, str] = {}
    for s in statement.get("subject", []):
        d = s.get("digest", {})
        if "name" in s and "sha256" in d:
            assets[s["name"]] = d["sha256"]
        elif "sha1" in d and s.get("uri", "").startswith("pkg:github/"):
            commit = d["sha1"]
    return commit, assets
