"""OpenPGP verification against a pinned fingerprint, using throwaway GNUPGHOME directories."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import net
from .config import normalize_fpr


class GpgError(Exception):
    pass


@dataclass
class SigCheck:
    """Interpretation of ``gpg --status-fd`` output against a pinned fingerprint."""

    outcome: str  # valid | bad | wrong-key | expired-key | revoked-key | no-key | error
    signer_primary: str | None = None
    signer_key: str | None = None
    status: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return self.outcome == "valid"


def parse_status(status_text: str, pinned_fpr: str) -> SigCheck:
    """Classify a signature from gpg status lines.

    A signature is only "valid" when gpg emitted GOODSIG and a VALIDSIG whose primary-key (or
    signing-key) fingerprint equals the pinned fingerprint. Trust-db output is ignored: the pin is
    the trust anchor.
    """
    pinned = normalize_fpr(pinned_fpr)
    lines = [l[len("[GNUPG:] "):] for l in status_text.splitlines() if l.startswith("[GNUPG:] ")]
    kw = {l.split(" ", 1)[0] for l in lines}
    primary = signing = None
    for l in lines:
        parts = l.split()
        if parts[0] == "VALIDSIG" and len(parts) >= 2:
            signing = parts[1].upper()
            primary = parts[10].upper() if len(parts) >= 11 else signing
    check = SigCheck("error", primary, signing, lines)
    if "BADSIG" in kw:
        check.outcome = "bad"
    elif "REVKEYSIG" in kw:
        check.outcome = "revoked-key"
    elif "NO_PUBKEY" in kw or ("ERRSIG" in kw and not primary):
        check.outcome = "no-key"
    elif primary and pinned not in (primary, signing):
        check.outcome = "wrong-key"
    elif "EXPKEYSIG" in kw and primary:
        check.outcome = "expired-key"
    elif "GOODSIG" in kw and primary:
        check.outcome = "valid"
    return check


class Keyring:
    """A temporary GNUPGHOME holding only explicitly imported keys."""

    def __init__(self):
        self.home = Path(tempfile.mkdtemp(prefix="rv-gnupg-"))
        os.chmod(self.home, 0o700)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        # Stop any agent spawned for this home before removing it.
        subprocess.run(["gpgconf", "--homedir", str(self.home), "--kill", "all"], capture_output=True)
        shutil.rmtree(self.home, ignore_errors=True)

    @property
    def env(self) -> dict[str, str]:
        return {**os.environ, "GNUPGHOME": str(self.home)}

    def _gpg(self, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["gpg", "--batch", "--no-tty", "--homedir", str(self.home), *args],
            input=input_bytes,
            capture_output=True,
            env=self.env,
        )

    def import_key_data(self, data: bytes) -> None:
        p = self._gpg("--import", input_bytes=data)
        if p.returncode not in (0, 2):  # 2 = some keys skipped (e.g. unusable uids), still imported
            raise GpgError(f"gpg --import failed: {p.stderr.decode(errors='replace').strip()}")

    def fingerprints(self) -> set[str]:
        """Primary-key fingerprints in this keyring."""
        p = self._gpg("--with-colons", "--fingerprint", "--list-keys")
        fprs, last = set(), None
        for line in p.stdout.decode().splitlines():
            f = line.split(":")
            if f[0] == "fpr" and last == "pub":
                fprs.add(f[9].upper())
            last = f[0]
        return fprs

    def verify_detached(self, signature: Path, data: Path, pinned_fpr: str) -> SigCheck:
        p = self._gpg("--status-fd", "1", "--verify", str(signature), str(data))
        return parse_status(p.stdout.decode(errors="replace"), pinned_fpr)

    def verify_clearsigned(self, path: Path, pinned_fpr: str) -> tuple[SigCheck, bytes]:
        """Verify a clearsigned file and return exactly the signed content."""
        out = Path(self.home) / "clearsigned.out"
        p = self._gpg("--status-fd", "2", "--yes", "--output", str(out), "--decrypt", str(path))
        check = parse_status(p.stderr.decode(errors="replace"), pinned_fpr)
        content = out.read_bytes() if out.exists() else b""
        return check, content


DEFAULT_KEY_URLS = ["https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x{fingerprint}"]


def fetch_pinned_key(fingerprint: str, key_file: Path | None, key_urls: list[str] | None, cache_dir: Path) -> tuple[bytes, str]:
    """Return ``(armored key, source)`` for a pinned fingerprint, trying the bundled file, the cache,
    then key servers. The key material is only accepted if it actually contains the fingerprint.
    """
    fpr = normalize_fpr(fingerprint)
    sources: list[tuple[str, Any]] = []
    if key_file and key_file.is_file():
        sources.append((str(key_file), key_file.read_bytes))
    cached = cache_dir / "keys" / f"{fpr}.asc"
    if cached.is_file():
        sources.append((str(cached), cached.read_bytes))
    for url in key_urls if key_urls is not None else DEFAULT_KEY_URLS:
        u = url.format(fingerprint=fpr)
        sources.append((net.redact_url(u), lambda u=u: net.get_bytes(u)))
    errors = []
    for name, fetch in sources:
        try:
            data = fetch()
        except (OSError, net.HttpError) as e:
            errors.append(f"{name}: {e}")
            continue
        with Keyring() as probe:
            probe.import_key_data(data)
            present = fpr in probe.fingerprints()
        if present:
            if name.startswith("http"):
                cached.parent.mkdir(parents=True, exist_ok=True)
                cached.write_bytes(data)
            return data, name
        errors.append(f"{name}: key {fpr} not present")
    raise GpgError(f"could not load pinned key {fpr}: " + "; ".join(errors))
