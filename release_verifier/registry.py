"""Anonymous OCI distribution client (Docker Hub, GHCR, ...) for digest inspection."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from . import net

INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)
MANIFEST_TYPES = (
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
)
ACCEPT = ", ".join(INDEX_TYPES + MANIFEST_TYPES)
_HOSTS = {"docker.io": "registry-1.docker.io", "index.docker.io": "registry-1.docker.io"}


def parse_challenge(header: str) -> dict[str, str]:
    """``Bearer realm="...",service="...",scope="..."`` -> dict (scheme under key ``scheme``)."""
    scheme, _, rest = header.strip().partition(" ")
    out = {"scheme": scheme.lower()}
    for m in re.finditer(r'(\w+)="([^"]*)"', rest):
        out[m.group(1)] = m.group(2)
    return out


def platform_key(p: dict[str, Any]) -> str:
    """``os/arch[/variant]`` as the configs name platforms. Variants a runtime treats as the plain
    platform are dropped (``arm64/v8`` is ``arm64``; ``amd64/v2..v4`` run on ``amd64`` hosts), so a
    variant cannot make a published image look like a different, unchecked platform."""
    arch, variant = p.get("architecture"), p.get("variant")
    if (arch == "arm64" and variant == "v8") or arch == "amd64":
        variant = None
    return f"{p.get('os')}/{arch}" + (f"/{variant}" if variant else "")


def platform_manifests(index: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Runnable per-platform descriptors of an image index, and problems with the index.

    BuildKit attestation manifests (platform ``unknown/unknown`` with
    ``vnd.docker.reference.type: attestation-manifest``) are skipped: they are not images. A
    platform listed twice (after normalization) is a problem: a runtime may pick either one.
    """
    out: dict[str, dict[str, Any]] = {}
    problems: list[str] = []
    for d in index.get("manifests", []):
        ann = d.get("annotations") or {}
        if ann.get("vnd.docker.reference.type") == "attestation-manifest":
            continue
        p = d.get("platform") or {}
        if p.get("os") in (None, "unknown") or p.get("architecture") in (None, "unknown"):
            continue
        key = platform_key(p)
        if key in out:
            problems.append(f"index lists platform {key} more than once ({out[key]['digest']}, {d.get('digest')})")
            continue
        out[key] = d
    return out, problems


def index_problems(desc: dict[str, Any], platforms: list[str]) -> list[str]:
    """Compromise-class problems of a described tag against the platforms the flavor builds:
    duplicate platforms, and runnable platforms nobody rebuilds (a runtime on such a host would
    pull an image that no check covers)."""
    out = list(desc.get("problems", []))
    if desc.get("malformed"):
        out.append(f"malformed image index or manifest: {desc['malformed']}")
    unknown = sorted(desc.get("platforms", {}).keys() - set(platforms))
    if unknown:
        out.append(f"index carries platform(s) {', '.join(unknown)} that the release recipe does not build (expected {', '.join(platforms)})")
    return out


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class Registry:
    def __init__(self, registry: str, cache_dir: Path | None = None):
        self.name = registry
        self.host = _HOSTS.get(registry, registry)
        self.cache_dir = cache_dir
        self._tokens: dict[str, str | None] = {}
        self._challenge: dict[str, str] | None = None

    def _repo(self, repo: str) -> str:
        return f"library/{repo}" if self.host == "registry-1.docker.io" and "/" not in repo else repo

    def _auth(self, repo: str) -> dict[str, str]:
        if repo not in self._tokens:
            if self._challenge is None:
                try:
                    net.request(f"https://{self.host}/v2/", retries=1)
                    self._challenge = {}
                except net.HttpError as e:
                    hdr = getattr(e, "headers", {}).get("www-authenticate", "")
                    self._challenge = parse_challenge(hdr) if e.status == 401 and hdr else {}
            ch = self._challenge
            if ch.get("scheme") == "bearer" and ch.get("realm"):
                url = f"{ch['realm']}?scope=repository:{repo}:pull" + (f"&service={ch['service']}" if ch.get("service") else "")
                tok = net.get_json(url)
                self._tokens[repo] = tok.get("token") or tok.get("access_token")
            else:
                self._tokens[repo] = None
        t = self._tokens[repo]
        return {"Authorization": f"Bearer {t}"} if t else {}

    def _get(self, repo: str, path: str, method: str = "GET", accept: bool = True) -> tuple[dict[str, str], bytes]:
        """Authenticated request; pull tokens are short-lived (Docker Hub: 5 min), so a 401 on a
        cached token triggers one refresh."""
        url = f"https://{self.host}/v2/{repo}/{path}"
        for attempt in (0, 1):
            headers = {**({"Accept": ACCEPT} if accept else {}), **self._auth(repo)}
            try:
                _, h, data = net.request(url, headers, method=method)
                return h, data
            except net.HttpError as e:
                if e.status != 401 or attempt == 1 or not self._tokens.get(repo):
                    raise
                del self._tokens[repo]
        raise AssertionError("unreachable")

    def head(self, repo: str, ref: str) -> tuple[str, str] | None:
        """``(digest, media type)`` of a tag without counting as a Docker Hub pull; None if absent."""
        repo = self._repo(repo)
        try:
            headers, _ = self._get(repo, f"manifests/{ref}", method="HEAD")
        except net.HttpError as e:
            if e.status == 404:
                return None
            raise
        return headers.get("docker-content-digest", ""), headers.get("content-type", "").split(";")[0]

    def manifest(self, repo: str, ref: str) -> tuple[str, dict[str, Any]]:
        """Fetch a manifest/index; content-addressed results are cached and digest-checked."""
        repo = self._repo(repo)
        cache = self.cache_dir / "manifests" / f"{ref.replace(':', '_')}.json" if self.cache_dir and ref.startswith("sha256:") else None
        if cache and cache.is_file():
            data = cache.read_bytes()
            if digest_of(data) == ref:
                return ref, json.loads(data)
        _, data = self._get(repo, f"manifests/{ref}")
        digest = digest_of(data)
        if ref.startswith("sha256:") and digest != ref:
            raise ValueError(f"registry returned content with digest {digest} for {repo}@{ref}")
        if cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_bytes(data)
        return digest, json.loads(data)

    def blob_json(self, repo: str, digest: str) -> dict[str, Any]:
        repo = self._repo(repo)
        _, data = self._get(repo, f"blobs/{digest}", accept=False)
        if digest_of(data) != digest:
            raise ValueError(f"blob digest mismatch for {repo}@{digest}")
        return json.loads(data)

    def describe(self, repo: str, ref: str) -> dict[str, Any] | None:
        """Index digest plus per-platform manifest and config digests for a tag; None if absent."""
        head = self.head(repo, ref)
        if head is None:
            return None
        return self.describe_digest(repo, head[0])

    def describe_digest(self, repo: str, digest: str) -> dict[str, Any]:
        digest, doc = self.manifest(repo, digest)
        media = doc.get("mediaType", "")
        platforms: dict[str, dict[str, str]] = {}
        problems: list[str] = []
        if media in INDEX_TYPES or "manifests" in doc:
            descs, problems = platform_manifests(doc)
            for key, desc in descs.items():
                _, m = self.manifest(repo, desc["digest"])
                platforms[key] = {"manifest": desc["digest"], "config": m["config"]["digest"]}
        else:
            cfg = self.blob_json(repo, doc["config"]["digest"])
            platforms[platform_key(cfg)] = {"manifest": digest, "config": doc["config"]["digest"]}
        out = {"index_digest": digest, "media_type": media, "platforms": platforms}
        if problems:
            out["problems"] = problems
        return out
