"""GitHub REST access over plain HTTPS (works without a token; GITHUB_TOKEN raises rate limits)."""

from __future__ import annotations

import base64
import json
import urllib.parse
from typing import Any, Callable

from . import net

API = "https://api.github.com"


MAX_RELEASE_PAGES = 10


def releases(repo: str, limit: int, match: Callable[[dict[str, Any]], bool] = lambda r: True) -> list[dict[str, Any]]:
    """Releases newest first (published and, with a privileged token, drafts), paginating until
    ``limit`` of them satisfy ``match`` (or the listing ends, or MAX_RELEASE_PAGES pages were read).
    Returns every release read, so the caller also sees the ones that did not match."""
    out: list[dict[str, Any]] = []
    matched = 0
    for page in range(1, MAX_RELEASE_PAGES + 1):
        batch = net.get_json(f"{API}/repos/{repo}/releases?per_page=100&page={page}", net.github_headers())
        out.extend(batch)
        matched += sum(1 for r in batch if match(r))
        if matched >= limit or len(batch) < 100:
            break
    return out


def release_by_tag(repo: str, tag: str) -> dict[str, Any] | None:
    return net.get_optional_json(f"{API}/repos/{repo}/releases/tags/{urllib.parse.quote(tag, safe='')}", net.github_headers())


def list_dir(repo: str, ref: str, path: str) -> list[dict[str, Any]] | None:
    """Entries (``name``, ``type``, ``sha``) of a directory at ``ref``; None if it does not exist."""
    listing = net.get_optional_json(f"{API}/repos/{repo}/contents/{urllib.parse.quote(path)}?ref={urllib.parse.quote(ref, safe='')}", net.github_headers())
    return listing if isinstance(listing, list) else None


def tree_entry(repo: str, ref: str, path: str) -> dict[str, Any] | None:
    """``{"type", "sha"}`` of ``path`` at ``ref`` (a directory's sha is its git tree id); None if absent."""
    parent, _, name = path.rstrip("/").rpartition("/")
    listing = list_dir(repo, ref, parent) or []
    return next(({"type": e["type"], "sha": e["sha"]} for e in listing if e.get("name") == name), None)


def repo_snapshot(repo: str) -> dict[str, Any]:
    """Default branch, its head commit, and every path of that commit's tree (``{path: [type, sha]}``)."""
    info = net.get_json(f"{API}/repos/{repo}", net.github_headers())
    branch = info["default_branch"]
    commit = net.get_json(f"{API}/repos/{repo}/commits/{urllib.parse.quote(branch, safe='')}", net.github_headers())
    tree = net.get_json(f"{API}/repos/{repo}/git/trees/{commit['commit']['tree']['sha']}?recursive=1", net.github_headers())
    return {
        "default_branch": branch,
        "commit": commit["sha"],
        "tree": {e["path"]: [e["type"], e["sha"]] for e in tree.get("tree", [])},
        "truncated": bool(tree.get("truncated")),
    }


def summarize_release(rel: dict[str, Any]) -> dict[str, Any]:
    """The mutable-state fields of a release that `watch` tracks."""
    return {
        "id": rel["id"],
        "tag": rel["tag_name"],
        "draft": rel.get("draft", False),
        "prerelease": rel.get("prerelease", False),
        "immutable": rel.get("immutable"),
        "published_at": rel.get("published_at"),
        "assets": {
            a["name"]: {
                "id": a["id"],
                "digest": a.get("digest"),
                "size": a.get("size"),
                "updated_at": a.get("updated_at"),
            }
            for a in rel.get("assets", [])
        },
    }


def download_url(repo: str, tag: str, asset: str) -> str:
    return f"https://github.com/{repo}/releases/download/{urllib.parse.quote(tag)}/{urllib.parse.quote(asset)}"


def raw_url(repo: str, ref: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{repo}/{ref}/{path}"


def attestation_bundles(repo: str, digest: str) -> list[dict[str, Any]]:
    """Sigstore bundles GitHub stores for a subject digest (``sha256:<hex>``); [] when none."""
    data = net.get_optional_json(f"{API}/repos/{repo}/attestations/{digest}?per_page=100", net.github_headers())
    if not data:
        return []
    return [a["bundle"] for a in data.get("attestations", []) if a.get("bundle")]


def bundle_predicate_type(bundle: dict[str, Any]) -> str | None:
    env = bundle.get("dsseEnvelope")
    if not env:
        return None
    try:
        return json.loads(base64.b64decode(env["payload"])).get("predicateType")
    except (ValueError, KeyError):
        return None
