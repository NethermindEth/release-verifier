"""`watch`: cheap snapshot of mutable release state, diffed against the previous snapshot."""

from __future__ import annotations

import datetime as _dt
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from . import channels as ch
from . import github, gitops, registry, trust
from .checksums import strip_algo
from .config import Project, render
from .gpg import GpgError, fetch_pinned_key
from .registry import Registry
from .results import Report, Result, Status, utc_now
from .state import State
from .versions import Version

log = logging.getLogger(__name__)
SNAPSHOT_SCHEMA = 1


# -- snapshot collection --------------------------------------------------------------------

def _parse_ts(ts: str | None) -> _dt.datetime | None:
    return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None


def _release_versions(project: Project, releases: dict[str, Any]) -> list[tuple[str, str]]:
    """``[(tag, version)]`` of published releases, newest version first."""
    out = [(t, project.version_of(t)) for t, r in releases.items() if not r.get("draft")]
    return sorted(((t, v) for t, v in out if v), key=lambda tv: Version(tv[1]), reverse=True)


def image_refs(project: Project, versions: list[str]) -> list[tuple[str, str, str, str | None]]:
    """``[(flavor, repo, tag, version or None for latest-style tags)]`` to track."""
    out = []
    for f in project.flavors:
        for repo in f["repos"]:
            for v in versions:
                out.append((f["name"], repo, render(f["version_tag"], {"version": v}), v))
            for lt in f.get("latest_tags", []):
                out.append((f["name"], repo, lt, None))
    return out


def collect(project: Project, state: State, prev: dict[str, Any] | None, verified: dict[str, Any] | None = None) -> dict[str, Any]:
    """Gather the current state. Components that fail are recorded in ``errors`` and carried over
    from the previous snapshot so a transient outage does not look like a deletion next time."""
    snap: dict[str, Any] = {"schema": SNAPSHOT_SCHEMA, "project": project.name, "taken_at": utc_now(), "errors": {}}
    prev = prev or {}
    verified = verified or {}
    window = int(project.watch["release_window"])

    def guarded(name: str, fn: Callable[[], Any], fallback: Any) -> Any:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - every component failure becomes an ERROR finding
            log.warning("%s: %s", name, e)
            snap["errors"][name] = str(e)
            return fallback

    with ThreadPoolExecutor(max_workers=2) as pool:
        tags_f = pool.submit(guarded, "tags", lambda: _collect_tags(project), prev.get("tags", {}))
        rel_f = pool.submit(guarded, "releases", lambda: _collect_releases(project, window, prev.get("releases", {}), verified),
                            (prev.get("releases", {}), [], prev.get("unmatched_releases", [])))
        snap["tags"] = tags_f.result()
        snap["releases"], snap["evicted"], snap["unmatched_releases"] = rel_f.result()

    if project.tags.get("upstream_signers_dir"):
        snap["signers"] = guarded("signers", lambda: _collect_signers(project), prev.get("signers"))
    versions = [v for _, v in _release_versions(project, snap["releases"])]
    snap["images"] = guarded("images", lambda: _collect_images(project, state, versions, prev.get("images", {}), snap["errors"]), prev.get("images", {}))

    channel_versions = [v for v in versions if not Version(v).is_prerelease][: int(project.watch["channel_window"])]
    verified_versions = {rec.get("version") or project.version_of(t) for t, rec in verified.items()}
    snap["channels"] = {}
    for c in project.channels:
        name = c.get("name", c["type"])
        snap["channels"][name] = guarded(
            f"channel:{name}", lambda c=c: _collect_channel(project, state, c, verified_versions, channel_versions),
            (prev.get("channels") or {}).get(name),
        )
    return snap


def _collect_tags(project: Project) -> dict[str, Any]:
    tags = gitops.ls_remote_tags(project.git_url)
    return {t: v for t, v in tags.items() if project.version_of(t)}


def _collect_signers(project: Project) -> dict[str, Any]:
    """The upstream release-signers directory on the default branch (its git tree id)."""
    path = project.tags["upstream_signers_dir"]
    entry = github.tree_entry(project.repo, project.default_branch, path)
    return {"branch": project.default_branch, "path": path, "tree": entry["sha"] if entry and entry["type"] == "dir" else None}


def _collect_releases(project: Project, window: int, prev_releases: dict[str, Any], verified: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    """The newest ``window`` releases whose tag matches the pattern (paginating past any number of
    others), every release with a verification record, ``evicted`` (unverified tracked releases
    that only aged out of the window) and ``unmatched`` (published releases in the window's time
    range whose tag does not match the pattern and is not in ``releases.ignore_tag_patterns``).

    A tracked or verified release missing from the listing is looked up by tag. A verified release
    is always kept (its assets and image tags stay checked). An unverified one that is still there,
    unchanged and older than the window is evicted; otherwise it is kept, so the diff reports any
    change. Gone (404): left out, so the diff reports it as disappeared. An API error fails the
    whole collection, which then carries the previous state forward."""
    raw = github.releases(project.repo, window, match=lambda r: bool(project.version_of(r["tag_name"])))
    matching = [r for r in raw if project.version_of(r["tag_name"])][:window]
    cur = {r["tag_name"]: github.summarize_release(r) for r in matching}
    published = [_parse_ts(r["published_at"]) for r in cur.values() if r.get("published_at")]
    oldest = min(published) if published else None
    unmatched = sorted(r["tag_name"] for r in raw if not project.version_of(r["tag_name"]) and not project.release_ignored(r["tag_name"]) and not r.get("draft")
                       and (oldest is None or (_parse_ts(r.get("published_at")) or oldest) >= oldest))
    full = len(matching) >= window
    listed = {r["tag_name"]: r for r in raw}
    evicted = []
    for tag in sorted((prev_releases.keys() | {t for t in verified if project.version_of(t)}) - cur.keys()):
        rel = listed.get(tag) or github.release_by_tag(project.repo, tag)
        if rel is None:
            continue
        summary = github.summarize_release(rel)
        pts = _parse_ts(summary.get("published_at"))
        if tag not in verified and full and oldest and pts and pts < oldest and summary == prev_releases.get(tag):
            evicted.append(tag)
        else:
            cur[tag] = summary
    return cur, evicted, unmatched


def _collect_images(project: Project, state: State, versions: list[str], prev_images: dict[str, Any], errors: dict[str, str]) -> dict[str, Any]:
    """Per image tag: a lookup failure is an error for that tag only (its previous entry is kept);
    content the client cannot parse is recorded as ``malformed`` (a finding, not an error)."""
    if not project.flavors:
        return {}
    reg = Registry(project.images.get("registry", "docker.io"), state.cache_dir)

    def one(ref: tuple[str, str, str, str | None]) -> tuple[str, dict[str, Any] | None, str | None]:
        flavor, repo, tag, version = ref
        key = f"{repo}:{tag}"
        try:
            head = reg.head(repo, tag)
            if head is None:
                return key, None, None
            digest, _ = head
            p = prev_images.get(key)
            if p and p.get("index_digest") == digest and not p.get("malformed"):
                entry = dict(p)
            else:
                try:
                    entry = reg.describe_digest(repo, digest)
                except (ValueError, KeyError, TypeError) as e:
                    entry = {"index_digest": digest, "platforms": {}, "malformed": f"{type(e).__name__}: {e}"}
        except Exception as e:  # noqa: BLE001 - transport/registry failure of this tag only
            log.warning("image %s: %s", key, e)
            return key, prev_images.get(key), str(e)
        entry.update({"flavor": flavor, "version": version})
        return key, entry, None

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(one, image_refs(project, versions)))
    errors.update({f"image:{k}": err for k, _, err in results if err})
    return {k: v for k, v, _ in results if v is not None}


def _collect_channel(project: Project, state: State, c: dict[str, Any], verified_versions: set[str], channel_versions: list[str]) -> Any:
    if c["type"] == "homebrew":
        return ch.fetch_homebrew(c)
    if c["type"] == "winget":
        return {"listed": ch.winget_versions(c), "manifests": {v: ch.fetch_winget(c, v) for v in channel_versions}}
    if c["type"] == "ppa":
        key = None
        if c.get("dsc_signing_fingerprint"):
            same = c["dsc_signing_fingerprint"].replace(" ", "").upper() == project.fingerprint
            try:
                key, _ = fetch_pinned_key(
                    c["dsc_signing_fingerprint"], project.key_file() if same else None, c.get("key_urls"), state.cache_dir
                )
            except GpgError as e:
                raise RuntimeError(f"PPA upload key unavailable: {e}") from None
        return ch.fetch_ppa(c, verified_versions, key)
    raise ValueError(f"unknown channel type {c['type']}")


# -- evaluation (pure) ----------------------------------------------------------------------

def expected_assets(project: Project, snap: dict[str, Any], verified: dict[str, Any], tag: str, platforms: list[str]) -> dict[str, dict[str, str]]:
    """Platform -> expected asset/url/hash for a release, preferring hashes recorded by `verify`."""
    rel = snap.get("releases", {}).get(tag)
    version = project.version_of(tag)
    commit = (snap.get("tags", {}).get(tag) or {}).get("commit") or (verified.get(tag) or {}).get("commit")
    if not rel or not version or not commit:
        return {}
    vrec = verified.get(tag) or {}
    out = {}
    for p in platforms:
        name = project.asset_name(version, commit, p)
        a = rel["assets"].get(name)
        if not a:
            continue
        if name in vrec.get("assets", {}) and vrec.get("outcome") == "pass":
            sha, source = vrec["assets"][name], "verified"
        else:
            sha, source = strip_algo(a.get("digest")), "GitHub asset digest (release not verified yet)"
        out[p] = {"asset": name, "url": github.download_url(project.repo, tag, name), "sha256": sha, "source": source}
    return out


def evaluate(project: Project, snap: dict[str, Any], verified: dict[str, Any]) -> list[Result]:
    """Checks that hold for any single snapshot (run on the baseline too)."""
    out: list[Result] = []
    for comp, err in snap.get("errors", {}).items():
        out.append(Result("collect", Status.ERROR, comp, f"could not collect state: {err}"))
    if project.tags.get("upstream_signers_dir") and "signers" not in snap.get("errors", {}):
        out.append(_evaluate_signers(project, snap.get("signers") or {}))
    tags, releases, images = snap.get("tags", {}), snap.get("releases", {}), snap.get("images", {})
    grace = _dt.timedelta(seconds=int(project.watch["asset_upload_grace_seconds"]))

    if "releases" not in snap.get("errors", {}):
        for tag in snap.get("unmatched_releases", []):
            out.append(Result("release-pattern", Status.WARN, tag, f"published release whose tag does not match {project.tags['pattern']}; not tracked or verified"))
        for tag in sorted(t for t in verified if project.version_of(t) and t not in releases):
            out.append(Result("release", Status.FAIL, tag, "verified release is no longer published"))

    for tag, rel in releases.items():
        if rel.get("draft"):
            continue
        if tag not in tags and "tags" not in snap.get("errors", {}):
            out.append(Result("release-tag", Status.FAIL, tag, "published release has no git tag"))
        pub = _parse_ts(rel.get("published_at"))
        for name, a in rel["assets"].items():
            upd = _parse_ts(a.get("updated_at"))
            if pub and upd and upd > pub + grace:
                out.append(Result("asset-after-publication", Status.WARN, f"{tag}/{name}", f"asset updated at {a['updated_at']}, after publication at {rel['published_at']}"))
        vrec = verified.get(tag)
        if vrec:
            if tag in tags and tags[tag]["commit"] != vrec.get("commit"):
                out.append(Result("verified-tag", Status.FAIL, tag, f"tag now points to {tags[tag]['commit']}, verified commit was {vrec.get('commit')}"))
            for name, sha in vrec.get("assets", {}).items():
                cur = strip_algo((rel["assets"].get(name) or {}).get("digest"))
                if name not in rel["assets"]:
                    out.append(Result("verified-asset", Status.FAIL, f"{tag}/{name}", "verified asset is gone from the release"))
                elif cur and cur != sha:
                    out.append(Result("verified-asset", Status.FAIL, f"{tag}/{name}", f"GitHub digest {cur} differs from verified {sha}"))

    # Image pointers.
    flavors = {f["name"]: f for f in project.flavors}
    for key, img in images.items():
        flavor = flavors.get(img.get("flavor"))
        if not flavor:
            continue
        repo, _, itag = key.rpartition(":")
        for problem in registry.index_problems(img, flavor["platforms"]):
            out.append(Result("image-index", Status.FAIL, key, problem, {"digest": img["index_digest"]}))
        if img.get("version"):
            vtag = next((t for t in releases if project.version_of(t) == img["version"]), None)
            vrec = verified.get(vtag) if vtag else None
            rec = (vrec or {}).get("images", {}).get(key)
            if rec and rec.get("index_digest") != img["index_digest"]:
                out.append(Result("image-tag", Status.FAIL, key, f"version tag now {img['index_digest']}, verified digest was {rec.get('index_digest')}"))
            elif vrec and not rec and _seen_absent(vrec, key):
                out.append(Result("image-tag", Status.FAIL, key, f"version tag appeared after {vtag} was verified without it (now {img['index_digest']}); "
                                  "a late push is not covered by the verification"))
            continue
        out.append(_evaluate_latest(project, key, img, images, releases, verified, flavor))

    # Channels.
    for c in project.channels:
        name = c.get("name", c["type"])
        data = (snap.get("channels") or {}).get(name)
        if data is None or f"channel:{name}" in snap.get("errors", {}):
            continue
        out.extend(evaluate_channel(project, snap, verified, c, data))
    return out


def _seen_absent(vrec: dict[str, Any], key: str) -> bool:
    """`verify` looked for this image tag and found none (coverage ``absent``/``missing``)."""
    statuses = {s for k, s in ((vrec.get("coverage") or {}).get("images") or {}).items() if k.rpartition("@")[0] == key}
    return bool(statuses) and statuses <= {trust.ABSENT, "missing"}


def _evaluate_signers(project: Project, up: dict[str, Any]) -> Result:
    """`verify` trusts only the signers pinned here; a change upstream needs a reviewed pin update."""
    pinned = gitops.tree_hash(project.signers_dir())
    where = f"{project.repo}:{up.get('branch', project.default_branch)}:{up.get('path', project.tags['upstream_signers_dir'])}"
    details = {"pinned_tree": pinned, "upstream_tree": up.get("tree"), "pinned_dir": project.tags["signers_dir"]}
    if not up.get("tree"):
        return Result("release-signers", Status.SKIPPED, where, "upstream has no release-signers directory yet; tags are authenticated against the pinned copy only", details)
    if up["tree"] != pinned:
        return Result("release-signers", Status.FAIL, where, "upstream release signers changed; review the change and update the pin "
                      f"({project.tags['signers_dir']}) in this repository", details)
    return Result("release-signers", Status.PASS, where, f"upstream release signers equal the pinned copy ({pinned[:12]})", details)


def newest_trusted(project: Project, verified: dict[str, Any], releases: dict[str, Any]) -> tuple[str, str] | None:
    """``(tag, version)`` of the newest trusted, non-prerelease verified release."""
    best = None
    for tag, rec in verified.items():
        version = rec.get("version") or project.version_of(tag)
        if not version or Version(version).is_prerelease or (releases.get(tag) or {}).get("prerelease") or trust.gaps(rec):
            continue
        if best is None or Version(version) > Version(best[1]):
            best = (tag, version)
    return best


def _evaluate_latest(project, key, img, images, releases, verified, flavor) -> Result:
    digest = img["index_digest"]
    repo = key.rpartition(":")[0]
    for vtag, vrec in verified.items():
        version = vrec.get("version") or project.version_of(vtag)
        rec = vrec.get("images", {}).get(f"{repo}:{render(flavor['version_tag'], {'version': version})}")
        if rec and rec.get("index_digest") == digest:
            if vrec.get("outcome") == "fail":
                return Result("latest-tag", Status.FAIL, key, f"points to {vtag}, whose verification FAILED", {"digest": digest})
            if vrec.get("outcome") != "pass":
                return Result("latest-tag", Status.WARN, key, f"points to {vtag}, whose verification was inconclusive", {"digest": digest})
            if (releases.get(vtag) or {}).get("prerelease"):
                return Result("latest-tag", Status.WARN, key, f"points to pre-release {vtag}", {"digest": digest})
            if missing := trust.gaps(vrec):
                return Result("latest-tag", Status.WARN, key, f"points to {vtag}, which passed verification without the coverage needed to trust it: "
                              f"{'; '.join(missing)}; run a full verify", {"digest": digest, "missing_coverage": missing})
            newest = newest_trusted(project, verified, releases)
            if newest and Version(version) < Version(newest[1]):
                return Result("latest-tag", Status.WARN, key, f"points to {vtag}, older than the newest trusted release {newest[0]} (rolled back?)",
                              {"digest": digest, "newest_trusted": newest[0]})
            return Result("latest-tag", Status.PASS, key, f"points to verified release {vtag}", {"digest": digest})
    for other_key, other in images.items():
        if other.get("version") and other.get("flavor") == img.get("flavor") and other["index_digest"] == digest:
            return Result("latest-tag", Status.WARN, key, f"points to {other_key}, which has not been verified yet; run verify", {"digest": digest})
    return Result("latest-tag", Status.FAIL, key, "points to a digest that matches no known release image", {"digest": digest})


def evaluate_channel(project: Project, snap, verified, c: dict[str, Any], data: Any) -> list[Result]:
    """Everything the channel publishes, not only the versions we expect: every entry's hash, the
    channel's executable content (the Homebrew formula against its pinned template, the PPA source
    package against the authenticated source tree recorded by `verify`, pinned winget manifest
    fields), and any published version or package that does not correspond to a release."""
    name = c.get("name", c["type"])
    releases = snap.get("releases", {})
    tag_of = {project.version_of(t): t for t in releases}
    out: list[Result] = []

    def check(version: str, entries: list[dict[str, str]]) -> str | None:
        tag = tag_of.get(version)
        if not tag:
            out.append(Result("channel-hash", Status.WARN, f"{name}@{version}", "channel version has no release in the watched window"))
            return None
        exp = expected_assets(project, snap, verified, tag, c["platforms"])
        if not exp and "tags" in snap.get("errors", {}):
            out.append(Result("channel-hash", Status.SKIPPED, f"{name}@{version}", "release commit unknown because tag collection failed; hashes not compared this run"))
            return None
        out.extend(ch.evaluate(name, version, entries, exp, c["platforms"]))
        return tag

    if c["type"] == "homebrew":
        _homebrew(project, snap, verified, c, data, out, check)
    elif c["type"] == "winget":
        for version in data.get("listed") or []:
            if not _known_release(project, snap, version):
                out.append(Result("channel-version", Status.FAIL, f"{name}@{version}", "winget has a manifest for a version that is not a release of this project"))
        for version, manifest in (data.get("manifests") or {}).items():
            if manifest is None:
                out.append(Result("channel-hash", Status.INFO, f"{name}@{version}", "no manifest published (yet)"))
            elif "malformed" in manifest:
                out.append(Result("channel-content", Status.FAIL, f"{name}@{version}", f"manifest cannot be parsed safely: {manifest['malformed']}"))
            else:
                if (tag := tag_of.get(version)) and (pending := _pending(name, version, tag, verified)):
                    out.append(pending)
                if check(version, manifest["entries"]) and c.get("pinned_fields"):
                    out.append(ch.evaluate_pinned_fields(f"{name}@{version}", manifest.get("fields") or {}, c["pinned_fields"]))
    elif c["type"] == "ppa":
        for pkg, versions in (data.get("other_packages") or {}).items():
            out.append(Result("channel-version", Status.FAIL, f"{name}:{pkg}", f"the PPA publishes source package {pkg} ({', '.join(versions)}); only {c['source_package']} is expected"))
        legacy = c.get("legacy_uploads") or {}
        for version, pub in (data.get("sources") or {}).items():
            subject = f"{name}@{version}"
            if "error" in pub:
                out.append(Result("channel-fetch", Status.ERROR, subject, pub["error"]))
                continue
            if version in legacy:
                got = pub.get("legacy_dsc_sha256")
                if got == legacy[version]:
                    out.append(Result("channel-version", Status.PASS, subject, "legacy upload: .dsc equals the one pinned in legacy_uploads"))
                else:
                    out.append(Result("channel-version", Status.FAIL, subject, f"legacy upload changed: .dsc sha256 {got or pub.get('malformed')} != pinned {legacy[version]}"))
                continue
            tag = tag_of.get(version)
            if not tag or (releases.get(tag) or {}).get("draft"):
                out.append(Result("channel-version", Status.FAIL, subject, "the PPA publishes a version without a published GitHub release "
                                  "(apt installs the highest version, running its maintainer scripts as root)"))
                continue
            if pending := _pending(name, version, tag, verified):
                out.append(pending)
                continue
            if "malformed" in pub:
                out.append(Result("channel-content", Status.FAIL, subject, f"published source package cannot be accepted: {pub['malformed']}"))
                continue
            sig = pub.get("dsc_signature")
            if sig is not None and sig != "valid":
                out.append(Result("ppa-upload-signature", Status.FAIL, subject, f".dsc signature: {sig} (expected pinned key)"))
            elif sig == "valid":
                out.append(Result("ppa-upload-signature", Status.PASS, subject, ".dsc signed by the pinned key"))
            if not pub.get("tarball_matches_dsc"):
                out.append(Result("ppa-source-integrity", Status.FAIL, subject, "source tarball does not match the .dsc checksums"))
            for problem in pub.get("problems", []):
                out.append(Result("ppa-source-integrity", Status.FAIL, subject, problem))
            if check(version, pub["entries"]) and c.get("source_dir"):
                out.extend(_ppa_content(c, verified.get(tag) or {}, tag, version, pub))
    return out


def _pending(name: str, version: str, tag: str, verified: dict[str, Any]) -> Result | None:
    """A channel version of a published release: WARN until `verify` ran for it (publishing jobs
    upload minutes after the release), FAIL if its verification failed; None once it passed."""
    outcome = (verified.get(tag) or {}).get("outcome")
    if outcome is None:
        return Result("channel-version", Status.WARN, f"{name}@{version}", f"pending verification of {tag}; run verify")
    if outcome == "fail":
        return Result("channel-version", Status.FAIL, f"{name}@{version}", f"the channel publishes {tag}, whose verification FAILED")
    return None


def _known_release(project: Project, snap: dict[str, Any], version: str) -> bool:
    """A tracked release, or an older version that has a release tag (channels keep old versions)."""
    releases = snap.get("releases", {})
    if version in {project.version_of(t) for t in releases}:
        return True
    try:
        v = Version(version)
    except ValueError:
        return False
    newest = max((Version(project.version_of(t)) for t, r in releases.items() if not r.get("draft")), default=None)
    tagged = "tags" in snap.get("errors", {}) or version in {project.version_of(t) for t in snap.get("tags", {})}
    return bool(newest and v < newest and tagged)


def _homebrew(project: Project, snap, verified, c: dict[str, Any], data: dict[str, Any], out: list[Result], check) -> None:
    """The tap brew loads (default branch, every path) and the formula in it."""
    name = c.get("name", c["type"])
    tap = data.get("tap")
    if tap:
        if tap["default_branch"] != c.get("branch", "main"):
            out.append(Result("channel-tap", Status.FAIL, name, f"tap default branch is {tap['default_branch']}, expected {c.get('branch', 'main')} (brew follows the default branch)"))
        allowed = set(c.get("allowed_paths") or [c["path"]])
        extra = sorted(p for p, (kind, _) in tap["tree"].items() if kind != "tree" and p not in allowed)
        if extra or tap.get("truncated"):
            out.append(Result("channel-tap", Status.FAIL, name, f"tap contains paths outside allowed_paths: {', '.join(extra[:10]) or '(tree listing truncated)'} "
                              "(brew also loads Formula/, HomebrewFormula/, tap_migrations.json, formula_renames.json, cmd/)", {"commit": tap["commit"], "paths": extra}))
        else:
            out.append(Result("channel-tap", Status.PASS, name, f"tap {tap['default_branch']}@{tap['commit'][:12]} holds only the allowed paths"))
    version = data.get("version")
    if "malformed" in data:
        out.append(Result("channel-content", Status.FAIL, name, f"formula cannot be parsed: {data['malformed']}"))
        return
    if not version:
        out.append(Result("channel-hash", Status.FAIL, name, "formula has no version"))
        return
    subject = f"{name}@{version}"
    if not _known_release(project, snap, version):
        out.append(Result("channel-version", Status.FAIL, subject, "formula version is not a release of this project"))
    newest = newest_trusted(project, verified, snap.get("releases", {}))
    try:
        older = bool(newest) and Version(version) < Version(newest[1])
    except ValueError:
        older = False
    if older:
        since = _parse_ts((verified.get(newest[0]) or {}).get("verified_at"))
        grace = _dt.timedelta(hours=float(project.watch["channel_grace_hours"]))
        recent = since is not None and _dt.datetime.now(_dt.timezone.utc) - since < grace
        out.append(Result("channel-version", Status.WARN if recent else Status.FAIL, subject,
                          f"formula is at {version}, older than the newest trusted release {newest[0]}"
                          + (f" (verified less than {project.watch['channel_grace_hours']} h ago; the tap may not be updated yet)" if recent else "")))
    tag = check(version, data["entries"]) if version in {project.version_of(t) for t in snap.get("releases", {})} else None
    if c.get("template"):
        out.append(_template_content(project, snap, verified, c, tag, version, data.get("text")))


def _template_content(project: Project, snap, verified, c: dict[str, Any], tag: str | None, version: str, text: str | None) -> Result:
    """The formula against the pinned template: rendered with the release's hashes when the release
    is tracked, else with only the URL/hash slots open (the body is always compared)."""
    subject = f"{c.get('name', c['type'])}@{version}"
    if text is None:
        return Result("channel-content", Status.ERROR, subject, "the collected channel data has no file content to compare")
    template = project.channel_template(c)
    try:
        if tag:
            return ch.evaluate_template(subject, text, ch.render_template(template, version, expected_assets(project, snap, verified, tag, c["platforms"])), c["template"])
    except KeyError:
        pass  # no asset hash for a platform: fall back to the shape check
    except ValueError as e:
        return Result("channel-content", Status.ERROR, subject, f"pinned template {c['template']}: {e}")
    return ch.evaluate_template_shape(subject, text, template, version, c["template"])


def _ppa_content(c: dict[str, Any], vrec: dict[str, Any], tag: str, version: str, pub: dict[str, Any]) -> list[Result]:
    """The trusted reference is the release's source tree, recorded by `verify` only for authenticated source."""
    subject = f"{c.get('name', c['type'])}@{version}"
    ref = (vrec.get("references") or {}).get(c.get("name", c["type"])) or {}
    if not vrec:
        reason = f"{tag} has not been verified (run verify)"
    elif (vrec.get("coverage") or {}).get("source") not in trust.AUTHENTICATED_SOURCES:
        reason = f"source of {tag} is not authenticated"
    elif "files" not in ref:
        reason = ref.get("unavailable") or f"the verification record of {tag} has no {c['source_dir']} reference (re-run verify)"
    else:
        reason = None
    if reason:
        return [Result("channel-content", Status.SKIPPED, subject, f"source package not compared with trusted source: {reason}; the hash checks do not cover its install scripts")]
    trees = pub.get("trees") or {}
    if not trees:
        return [Result("channel-content", Status.ERROR, subject, "the published source package tree was not collected")]
    trusted = f"{c['source_dir']} at {ref['commit'][:12]}"
    return [
        ch.evaluate_source_tree(subject if len(trees) == 1 else f"{subject} {tarball}", tree, ref["files"], c["changelog"], version, trusted)
        for tarball, tree in sorted(trees.items())
    ]


def diff(project: Project, prev: dict[str, Any], cur: dict[str, Any], verified: dict[str, Any]) -> list[Result]:
    """Changes between two snapshots that indicate tampering or need attention."""
    out: list[Result] = []
    errors = set(cur.get("errors", {}))

    if "tags" not in errors:
        pt, ct = prev.get("tags", {}), cur.get("tags", {})
        for t in sorted(pt.keys() - ct.keys()):
            out.append(Result("tag", Status.FAIL, t, "release tag deleted", {"was": pt[t]}))
        for t in sorted(pt.keys() & ct.keys()):
            if pt[t] != ct[t]:
                out.append(Result("tag", Status.FAIL, t, f"release tag moved: {pt[t]['object'][:12]} ({pt[t]['type']}) -> {ct[t]['object'][:12]} ({ct[t]['type']})", {"was": pt[t], "now": ct[t]}))
        for t in sorted(ct.keys() - pt.keys()):
            out.append(Result("tag", Status.INFO, t, f"new release tag ({ct[t]['type']}) -> {ct[t]['commit'][:12]}"))

    if "releases" not in errors:
        pr, cr = prev.get("releases", {}), cur.get("releases", {})
        evicted = set(cur.get("evicted", []))
        for t in sorted(pr.keys() - cr.keys()):
            if t in evicted:
                out.append(Result("release", Status.WARN, t, "unverified release left the watched window (still published, unchanged) and is no longer tracked; "
                                  "run verify for it to keep it tracked"))
            elif not pr[t].get("draft"):
                out.append(Result("release", Status.FAIL, t, "published release disappeared"))
        for t in sorted(pr.keys() & cr.keys()):
            out.extend(_diff_release(t, pr[t], cr[t]))
        for t in sorted(cr.keys() - pr.keys()):
            if cr[t].get("draft"):
                continue
            if t in verified:
                out.append(Result("release", Status.INFO, t, "release appeared in the watched window (already verified)"))
            else:
                out.append(Result("release", Status.WARN, t, "new release published; run `verify` for it"))

    if "images" not in errors:
        pi, ci = prev.get("images", {}), cur.get("images", {})
        cur_versions = {project.version_of(t) for t in cur.get("releases", {})}
        for key in sorted(pi.keys() | ci.keys()):
            a, b = pi.get(key), ci.get(key)
            version = (a or b).get("version")
            if a and b and a["index_digest"] != b["index_digest"]:
                if version:
                    out.append(Result("image-tag", Status.FAIL, key, f"immutable version tag re-pointed: {a['index_digest']} -> {b['index_digest']}", {"was": a, "now": b}))
                else:
                    out.append(Result("image-tag", Status.INFO, key, f"moved {a['index_digest']} -> {b['index_digest']}"))
            elif a and not b and version in cur_versions:
                out.append(Result("image-tag", Status.WARN, key, "version tag no longer exists in the registry"))
            elif b and not a and version:
                out.append(Result("image-tag", Status.INFO, key, f"new version tag -> {b['index_digest']}"))

    for c in project.channels:
        name = c.get("name", c["type"])
        if c["type"] == "homebrew" and f"channel:{name}" not in errors:
            a = (prev.get("channels") or {}).get(name) or {}
            b = (cur.get("channels") or {}).get(name) or {}
            if a.get("version") != b.get("version"):
                out.append(Result("channel", Status.INFO, name, f"version {a.get('version')} -> {b.get('version')}"))
    return out


def _diff_release(tag: str, a: dict[str, Any], b: dict[str, Any]) -> list[Result]:
    out: list[Result] = []
    published = not a.get("draft")
    sev = Status.FAIL if published else Status.INFO
    if a["id"] != b["id"]:
        out.append(Result("release", Status.FAIL if published else Status.INFO, tag, f"release was deleted and recreated (id {a['id']} -> {b['id']})"))
    for name in sorted(a["assets"].keys() - b["assets"].keys()):
        out.append(Result("release-asset", sev, f"{tag}/{name}", "asset removed after publication" if published else "asset removed from draft"))
    for name in sorted(b["assets"].keys() - a["assets"].keys()):
        out.append(Result("release-asset", sev, f"{tag}/{name}", "asset added after publication" if published else "asset added to draft", {"now": b["assets"][name]}))
    for name in sorted(a["assets"].keys() & b["assets"].keys()):
        x, y = a["assets"][name], b["assets"][name]
        if x != y:
            out.append(Result("release-asset", sev, f"{tag}/{name}", "asset replaced after publication" if published else "asset replaced in draft", {"was": x, "now": y}))
    for field in ("draft", "prerelease"):
        if a.get(field) != b.get(field):
            out.append(Result("release", Status.INFO, tag, f"{field}: {a.get(field)} -> {b.get(field)}"))
    if a.get("immutable") and not b.get("immutable"):
        out.append(Result("release", Status.WARN, tag, "release is no longer immutable"))
    return out


# -- command --------------------------------------------------------------------------------

def run(project: Project, state: State, accept: bool = False) -> Report:
    """Collect, evaluate and diff. A diff with compromise-class findings does not advance the
    baseline (so the finding repeats on every run) unless ``accept`` is set after investigation."""
    report = Report("watch", project.name)
    prev = state.load_snapshot()
    verified = state.load_verified()
    cur = collect(project, state, prev, verified)
    report.extend(evaluate(project, cur, verified))
    advance = True
    if prev is None:
        report.add("baseline", Status.INFO, project.name, f"first run: recorded baseline ({len(cur['tags'])} tags, {len(cur['releases'])} releases, {len(cur['images'])} image tags)")
    else:
        changes = diff(project, prev, cur, verified)
        report.extend(changes)
        report.meta["previous_snapshot"] = prev.get("taken_at")
        if any(r.status is Status.FAIL for r in changes) and not accept:
            advance = False
            report.add("baseline", Status.INFO, project.name, "baseline NOT advanced because of compromise-class changes; investigate, then run `watch --accept`")
    state.save_snapshot(cur, advance=advance)
    report.meta.update({"snapshot": cur["taken_at"], "baseline_advanced": advance})
    report.finished_at = utc_now()
    return report
