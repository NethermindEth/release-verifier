"""Git operations: remote tag listing, signed-tag verification, release checkouts."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .gpg import Keyring


class GitError(Exception):
    pass


def _git(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess:
    p = subprocess.run(
        ["git", "-c", "core.autocrlf=false", "-c", "advice.detachedHead=false", *args],
        cwd=cwd,
        capture_output=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", **(env or {})},
    )
    if check and p.returncode != 0:
        raise GitError(f"git {' '.join(args[:3])} failed: {p.stderr.decode(errors='replace').strip()[:500]}")
    return p


def parse_ls_remote(text: str) -> dict[str, dict[str, str]]:
    """``git ls-remote --tags`` output -> ``{tag: {object, type, commit}}``.

    Annotated tags appear twice (the tag object, then ``^{}`` with the peeled target); a tag without
    a peeled line is lightweight and its object is the commit itself.
    """
    objects: dict[str, str] = {}
    peeled: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        sha, _, ref = line.partition("\t")
        if not ref.startswith("refs/tags/"):
            continue
        name = ref[len("refs/tags/"):]
        if name.endswith("^{}"):
            peeled[name[:-3]] = sha
        else:
            objects[name] = sha
    out = {}
    for name, sha in objects.items():
        if name in peeled:
            out[name] = {"object": sha, "type": "tag", "commit": peeled[name]}
        else:
            out[name] = {"object": sha, "type": "commit", "commit": sha}
    return out


def ls_remote_tags(url: str) -> dict[str, dict[str, str]]:
    return parse_ls_remote(_git("ls-remote", "--tags", url).stdout.decode())


def tree_hash(directory: Path) -> str:
    """Git tree object id of a flat directory of regular files, as ``git write-tree`` would
    compute it, so a pinned copy can be compared with the upstream tree without a checkout."""
    entries = b""
    for p in sorted(directory.iterdir(), key=lambda p: p.name.encode()):
        if p.is_symlink() or not p.is_file():
            raise ValueError(f"{p}: only regular files are supported in a pinned signers directory")
        data = p.read_bytes()
        blob = hashlib.sha1(b"blob %d\0" % len(data) + data).digest()
        mode = b"100755" if p.stat().st_mode & 0o100 else b"100644"
        entries += mode + b" " + p.name.encode() + b"\0" + blob
    return hashlib.sha1(b"tree %d\0" % len(entries) + entries).hexdigest()


@dataclass
class TagVerification:
    ok: bool
    output: str


class SourceRepo:
    """A shallow local clone used for tag checks and rebuild checkouts."""

    def __init__(self, path: Path, url: str):
        self.path = path
        self.url = url
        if not (path / ".git").exists() and not (path / "HEAD").exists():
            path.mkdir(parents=True, exist_ok=True)
            _git("init", "-q", "--bare", str(path))
        _git("remote", "remove", "origin", cwd=path, check=False)
        _git("remote", "add", "origin", url, cwd=path)

    def git(self, *args: str, **kw) -> subprocess.CompletedProcess:
        return _git(*args, cwd=self.path, **kw)

    def fetch(self, tag: str) -> None:
        # Forced refspec: we want the remote's current state, even if the tag moved.
        self.git("fetch", "-q", "--depth=1", "--no-tags", "--force", "origin", f"+refs/tags/{tag}:refs/tags/{tag}")

    def object_type(self, ref: str) -> str:
        return self.git("cat-file", "-t", ref).stdout.decode().strip()

    def tag_headers(self, tag: str) -> dict[str, str]:
        """Header fields (``object``, ``type``, ``tag``, ``tagger``) of the annotated tag object. A
        field that appears more than once maps to ``""`` so it can never match an expected value."""
        out: dict[str, str] = {}
        for line in self.git("cat-file", "tag", f"refs/tags/{tag}").stdout.decode(errors="replace").split("\n"):
            if not line:
                break
            key, _, value = line.partition(" ")
            out[key] = "" if key in out else value
        return out

    def peel(self, tag: str) -> str:
        return self.git("rev-parse", f"refs/tags/{tag}^{{commit}}").stdout.decode().strip()

    def commit_time(self, commit: str) -> int:
        return int(self.git("log", "-1", "--format=%ct", commit).stdout.decode().strip())

    def archive(self, ref: str, path: str) -> bytes:
        """Tar of ``path`` at ``ref``, read from the object store (nothing is checked out or run)."""
        return self.git("archive", "--format=tar", ref, path).stdout

    def verify_tag(self, tag: str, signers: Path, allowed_signers_file: str, gpg_keys_glob: str) -> TagVerification:
        """``git verify-tag`` trusting only the signers pinned in ``signers`` (this repository)."""
        with Keyring() as kr:
            for key in sorted(signers.glob(gpg_keys_glob)):
                kr.import_key_data(key.read_bytes())
            allowed = signers / allowed_signers_file
            args = ["verify-tag", "-v", tag]
            if allowed.is_file():
                args = ["-c", f"gpg.ssh.allowedSignersFile={allowed}", *args]
            p = self.git(*args, env={"GNUPGHOME": str(kr.home)}, check=False)
        out = (p.stdout + p.stderr).decode(errors="replace")
        # Drop the tag message echoed by -v; keep the signature verdict lines.
        verdict = [l for l in out.splitlines() if any(s in l for s in ("signature", "Good", "BAD", "gpg:", "No principal", "Could not"))]
        return TagVerification(p.returncode == 0, "\n".join(verdict)[:2000])

    def checkout(self, commit: str, dest: Path) -> None:
        if dest.exists():
            self.remove_checkout(dest)
        self.git("worktree", "add", "-q", "--detach", "--force", str(dest), commit)

    def remove_checkout(self, dest: Path) -> None:
        self.git("worktree", "remove", "--force", str(dest), check=False)
        shutil.rmtree(dest, ignore_errors=True)
        self.git("worktree", "prune", check=False)
