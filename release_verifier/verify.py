"""`verify`: full verification of one release tag."""

from __future__ import annotations

import contextlib
import datetime as _dt
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import attest, github, gitops, rebuild, registry, trust
from . import channels as ch
from .checksums import ChecksumsError, parse_sha256sums, sha256_file, strip_algo
from .config import Project, render
from .gpg import Keyring, SigCheck, fetch_pinned_key
from .net import download
from .registry import Registry
from .results import Report, Result, Status, utc_now
from .state import State
from .trust import ABSENT
from .versions import Version, expected
from .watch import evaluate_channel, expected_assets

log = logging.getLogger(__name__)


@dataclass
class Options:
    tag: str
    work_dir: Path
    skip_rebuild: bool = False
    skip_image_rebuild: bool = False
    platforms: list[str] | None = None
    image_platforms: list[str] | None = None
    flavors: list[str] | None = None
    builder: str = "release-verifier"
    no_cache: bool = False
    keep_work: bool = False


@dataclass
class _Ctx:
    """Facts established while verifying, shared between the stages."""

    version: str = ""
    release: dict[str, Any] | None = None
    commit: str | None = None
    epoch: int | None = None
    assets: dict[str, dict[str, Any]] = field(default_factory=dict)  # GitHub API assets by name
    downloads: dict[str, Path] = field(default_factory=dict)
    hashes: dict[str, str] = field(default_factory=dict)  # sha256 of downloaded assets
    signed_ok: set[str] = field(default_factory=set)  # assets whose detached signature verified
    sums: dict[str, str] | None = None
    sums_signed: bool = False
    images: dict[str, Any] = field(default_factory=dict)
    src: gitops.SourceRepo | None = None
    checkout: Path | None = None
    source: str = "unauthenticated"  # signed | pinned | unauthenticated; gates running anything from the checkout
    source_note: str = "the tag was not authenticated"
    references: dict[str, Any] = field(default_factory=dict)  # channel -> trusted source reference (hashes only)
    # What was actually established per artifact (see trust.py); unset entries default to skipped/absent.
    coverage: dict[str, dict[str, str]] = field(default_factory=lambda: {"packages": {}, "images": {}, "channels": {}})


class Verifier:
    def __init__(self, project: Project, state: State, opts: Options):
        self.p = project
        self.state = state
        self.o = opts
        self.r = Report("verify", project.name, opts.tag)
        self.c = _Ctx()
        self.work = opts.work_dir / project.name / opts.tag
        self.log_file = self.work / "logs" / "rebuild.log"
        self.keyring: Keyring | None = None
        self._config_docs: dict[str, dict[str, Any]] = {}  # image config digest -> config document
        self._builder_ready = False  # buildx builder inspected (or created) once per run

    @contextlib.contextmanager
    def stage(self, name: str, subject: str | None = None):
        """Any unexpected exception inside a stage becomes an ERROR result instead of aborting."""
        t0 = time.monotonic()
        try:
            yield
        except Exception as e:  # noqa: BLE001
            log.exception("stage %s failed", name)
            self.r.add(name, Status.ERROR, subject or self.o.tag, f"{type(e).__name__}: {e}")
        finally:
            durations = self.r.meta.setdefault("durations_s", {})
            durations[name] = round(durations.get(name, 0) + time.monotonic() - t0, 1)

    # -- stages ---------------------------------------------------------------------------

    def run(self) -> Report:
        version = self.p.version_of(self.o.tag)
        if not version:
            self.r.add("tag-pattern", Status.ERROR, self.o.tag, f"tag does not match the project's tag pattern {self.p.tags['pattern']}")
            return self._finish()
        self.c.version = version
        self.work.mkdir(parents=True, exist_ok=True)
        self.r.meta.update({"version": version, "work_dir": str(self.work)})
        try:
            with self.stage("release"):
                self._release()
            if self.c.release is None:
                return self._finish()
            with self.stage("git-tag"):
                self._git_tag()
            if not self.c.commit:
                return self._finish()
            with self.stage("asset-names"):
                self._asset_names()
            with self.stage("signing-key"):
                self.keyring = Keyring()
                data, source = fetch_pinned_key(
                    self.p.fingerprint, self.p.key_file(), self.p.signing_key.get("key_urls"), self.state.cache_dir
                )
                self.keyring.import_key_data(data)
                self.r.meta["signing_key_source"] = source
            if self.keyring is None:
                return self._finish()
            with self.stage("assets"):
                self._download_and_check_signatures()
            with self.stage("extra-assets"):
                self._extra_assets()
            with self.stage("checksums"):
                self._checksums()
            with self.stage("release-attestation"):
                self._release_attestation()
            with self.stage("provenance"):
                self._provenance()
            if self.o.skip_rebuild:
                self.r.add("package-rebuild", Status.SKIPPED, self.o.tag, "--skip-rebuild given")
            elif self.p.package_rebuild and not self._source_authenticated():
                self.r.add("package-rebuild", Status.SKIPPED, self.o.tag, self._unauthenticated_message())
            elif self.p.package_rebuild:
                with self.stage("package-rebuild"):
                    self._package_rebuild()
            with self.stage("images"):
                self._images()
            with self.stage("channels"):
                self._channels()
        finally:
            if self.keyring:
                self.keyring.close()
            self._cleanup()
        return self._finish()

    def _finish(self) -> Report:
        self.r.finished_at = utc_now()
        if self.c.commit:
            record = {
                "version": self.c.version,
                "commit": self.c.commit,
                "verified_at": self.r.finished_at,
                "outcome": {0: "pass", 1: "fail", 2: "inconclusive"}[self.r.exit_code],
                "assets": {n: h for n, h in self.c.hashes.items() if n in self.c.signed_ok or (self.c.sums_signed and (self.c.sums or {}).get(n) == h)},
                "images": self.c.images,
                "coverage": self._coverage(),
                "references": self.c.references,
            }
            missing = trust.gaps(record)
            record["trusted"] = not missing
            self.r.meta["trusted"] = not missing
            if missing:
                self.r.add("coverage", Status.INFO, self.o.tag, f"not trusted as a verified release by watch: {'; '.join(missing)}", coverage=record["coverage"])
            else:
                self.r.add("coverage", Status.PASS, self.o.tag, "authenticated source; every published package and image rebuilt and matching", coverage=record["coverage"])
            record["counts"] = self.r.counts()
            self.state.record_verified(self.o.tag, record)
        return self.r

    def _coverage(self) -> dict[str, Any]:
        cov = self.c.coverage
        packages = {pl: ABSENT if name not in self.c.assets else cov["packages"].get(pl, "skipped") for pl, name in self._platform_assets().items()}
        images = dict(cov["images"])
        for flavor in self.p.flavors:
            vtag = render(flavor["version_tag"], {"version": self.c.version})
            for repo in flavor["repos"]:
                for platform in flavor["platforms"]:
                    images.setdefault(f"{repo}:{vtag}@{platform}", "skipped")
        extras = {}
        for name in self._extra_names():
            signed = name in self.c.signed_ok
            summed = self.c.sums_signed and name in self.c.hashes and (self.c.sums or {}).get(name) == self.c.hashes[name]
            extras[name] = trust.EXTRA_OK if signed and summed else "unchecksummed-not-rebuilt" if signed else "unsigned-not-rebuilt"
        return {"source": self.c.source, "packages": packages, "images": images, "extras": extras, "channels": dict(cov["channels"])}

    def _release(self) -> None:
        rel = github.release_by_tag(self.p.repo, self.o.tag)
        if rel is None:
            self.r.add("release", Status.ERROR, self.o.tag, "no published GitHub release for this tag (or it is a draft)")
            return
        self.c.release = rel
        self.c.assets = {a["name"]: a for a in rel.get("assets", [])}
        self.r.add("release", Status.PASS, self.o.tag, f"release {rel['id']} published {rel.get('published_at')} with {len(self.c.assets)} assets",
                   immutable=rel.get("immutable"), prerelease=rel.get("prerelease"))

    def _git_tag(self) -> None:
        t = self.p.tags
        src = gitops.SourceRepo(self.o.work_dir / self.p.name / "src.git", self.p.git_url)
        self.c.src = src
        src.fetch(self.o.tag)
        kind = src.object_type(f"refs/tags/{self.o.tag}")
        self.c.commit = src.peel(self.o.tag)
        self.c.epoch = src.commit_time(self.c.commit)
        self.r.meta["commit"] = self.c.commit
        signed: bool | None  # None: unsigned, but the release predates signed tags
        if kind == "tag":
            signers = self.p.signers_dir()
            v = src.verify_tag(self.o.tag, signers, t.get("allowed_signers_file", "allowed_signers"), t.get("gpg_keys_glob", "*.asc"))
            signed = v.ok
            if v.ok:
                self.r.add("signed-tag", Status.PASS, self.o.tag, f"annotated tag signed by a signer pinned in this repository ({t['signers_dir']})", commit=self.c.commit, output=v.output)
                if problem := self._tag_binding(src.tag_headers(self.o.tag)):
                    signed = False
                    self.r.add("tag-binding", Status.FAIL, self.o.tag, problem)
                else:
                    self.r.add("tag-binding", Status.PASS, self.o.tag, "the signed tag object names this tag, points at the commit, and its version is newer than every verified release")
            else:
                self.r.add("signed-tag", Status.FAIL, self.o.tag, f"tag signature is not from a signer pinned in this repository ({t['signers_dir']})", output=v.output)
        elif expected(self.c.version, t.get("signed_expected_after")):
            signed = False
            self.r.add("signed-tag", Status.FAIL, self.o.tag, f"tag is a lightweight ({kind}) tag; signed annotated tags are required after {t.get('signed_expected_after')}")
        else:
            signed = None
            self.r.add("signed-tag", Status.LEGACY, self.o.tag, f"lightweight unsigned tag (releases <= {t.get('signed_expected_after')} predate signed tags)", commit=self.c.commit)
        self._authenticate_source(signed, (t.get("trusted_commits") or {}).get(self.o.tag))

    def _tag_binding(self, hdr: dict[str, str]) -> str | None:
        """A valid signature only says a signer signed *some* tag object. Bind it to this release:
        the signed ``tag`` header must be the ref name (no replay of another signed tag under a new
        name), it must tag the commit directly, and the version must be newer than every release
        verified before (no re-release of old code under a new number). Re-verifying the same tag
        at the same commit is allowed."""
        if hdr.get("tag") != self.o.tag:
            return f"signed tag object is for {hdr.get('tag')!r}, not {self.o.tag!r} (a signed tag replayed under another name)"
        if hdr.get("type") != "commit" or hdr.get("object") != self.c.commit:
            return f"signed tag object tags {hdr.get('type')} {hdr.get('object')}, not commit {self.c.commit}"
        verified = self.state.load_verified()
        if (verified.get(self.o.tag) or {}).get("commit") == self.c.commit:
            return None
        newer = sorted((rec["version"] for t, rec in verified.items()
                        if t != self.o.tag and rec.get("outcome") == "pass" and _is_version(rec.get("version")) and Version(rec["version"]) >= Version(self.c.version)),
                       key=Version)
        if newer:
            return f"version {self.c.version} is not newer than the already verified {newer[-1]}; a new signed release must have a higher version"
        return None

    def _authenticate_source(self, signed: bool | None, pin: str | None) -> None:
        """Decide whether the tagged source may be built. Only a valid tag signature, or (for releases
        predating signed tags) a commit pinned in this repository's config, authenticates it."""
        if pin:
            if pin != self.c.commit:
                self.r.add("source-pin", Status.FAIL, self.o.tag, f"tag resolves to {self.c.commit}, but tags.trusted_commits pins {pin}")
                self.c.source_note = "the tag does not resolve to the pinned commit"
                return
            self.r.add("source-pin", Status.PASS, self.o.tag, "tag resolves to the commit pinned in tags.trusted_commits", commit=pin)
        if signed:
            self.c.source = "signed"
        elif signed is None and pin:
            self.c.source = "pinned"
        elif signed is None:
            self.c.source_note = "unsigned tag without a tags.trusted_commits pin"
        elif any(r.check == "tag-binding" and r.status is Status.FAIL for r in self.r.results):
            self.c.source_note = "the signed tag is not bound to this release"
        else:
            self.c.source_note = "the tag signature did not verify"
        self.r.meta["source"] = self.c.source

    def _source_authenticated(self) -> bool:
        return self.c.source in trust.AUTHENTICATED_SOURCES

    def _unauthenticated_message(self) -> str:
        return f"source not authenticated ({self.c.source_note}); nothing from the checkout is executed"

    def _platform_assets(self) -> dict[str, str]:
        return {pl.name: self.p.asset_name(self.c.version, self.c.commit, pl.name) for pl in self.p.platforms}

    def _asset_names(self) -> None:
        a = self.p.assets
        known = set()
        for pl in self.p.platforms:
            name = self.p.asset_name(self.c.version, self.c.commit, pl.name)
            known |= {name, name + a.get("signature_suffix", ".asc")}
            if name in self.c.assets:
                continue
            if expected(self.c.version, pl.expected_after):
                self.r.add("asset-present", Status.FAIL, name, f"release is missing the {pl.name} package (built from commit {self.c.commit[:8]})")
            else:
                self.r.add("asset-present", Status.LEGACY, name, f"{pl.name} packages started after {pl.expected_after}")
        if a.get("checksums_file"):
            known |= {a["checksums_file"], a.get("checksums_signature", a["checksums_file"] + ".asc")}
        known |= {n for x in self._extra_names(all_names=True) for n in (x, x + a.get("signature_suffix", ".asc"))}
        for name in sorted(self.c.assets.keys() - known):
            self.r.add("asset-unexpected", Status.WARN, name, "asset not described by the project config (wrong commit in name, or a new artifact type)")

    def _extra_names(self, all_names: bool = False) -> list[str]:
        """Rendered ``assets.extra_allowed`` names (only those the release publishes, by default)."""
        ctx = {"version": self.c.version, "sha8": self.c.commit[:8], "commit": self.c.commit}
        names = [render(x, ctx) for x in self.p.assets.get("extra_allowed", [])]
        return [n for n in names if all_names or n in self.c.assets]

    def _verify_sig(self, name: str, sig_name: str) -> SigCheck | None:
        sig = self.c.assets.get(sig_name)
        if not sig:
            self.r.add("gpg-signature", Status.FAIL, name, f"no detached signature {sig_name}")
            return None
        sig_path = self.work / "downloads" / sig_name
        download(sig["browser_download_url"], sig_path)
        check = self.keyring.verify_detached(sig_path, self.c.downloads[name], self.p.fingerprint)
        status = {"valid": Status.PASS, "expired-key": Status.WARN}.get(check.outcome, Status.FAIL)
        msg = {
            "valid": f"valid signature by pinned key {self.p.fingerprint}",
            "expired-key": "signature by the pinned key, but the key has expired",
        }.get(check.outcome, f"signature check failed: {check.outcome}")
        self.r.add("gpg-signature", status, name, msg, signer=check.signer_primary, status_lines=None if check.valid else check.status[-6:])
        if check.valid:
            self.c.signed_ok.add(name)
        return check

    def _fetch_asset(self, name: str) -> Path:
        a = self.c.assets[name]
        path = self.work / "downloads" / name
        api = strip_algo(a.get("digest"))
        if path.is_file() and api and sha256_file(path) == api:
            sha = api
        else:
            sha = download(a["browser_download_url"], path)
        self.c.downloads[name] = path
        self.c.hashes[name] = sha
        if api and api != sha:
            self.r.add("asset-digest", Status.FAIL, name, f"downloaded bytes {sha} differ from GitHub's recorded digest {api}")
        elif not api:
            self.r.add("asset-digest", Status.INFO, name, "GitHub returned no digest for this asset", sha256=sha)
        return path

    def _download_and_check_signatures(self) -> None:
        suffix = self.p.assets.get("signature_suffix", ".asc")
        for pl, name in self._platform_assets().items():
            if name not in self.c.assets:
                continue
            with self.stage("download", name):
                self._fetch_asset(name)
                self._verify_sig(name, name + suffix)

    def _extra_assets(self) -> None:
        """Allowed extra assets are not rebuilt; they are downloaded and signature-checked, and the
        coverage lists them as not rebuilt (trusted only when signed and in the signed checksums)."""
        a = self.p.assets
        suffix = a.get("signature_suffix", ".asc")
        for name in self._extra_names():
            with self.stage("download", name):
                self._fetch_asset(name)
                if name + suffix in self.c.assets or expected(self.c.version, a.get("extra_signed_expected_after")):
                    self._verify_sig(name, name + suffix)
                else:
                    self.r.add("gpg-signature", Status.LEGACY, name, f"unsigned extra asset (releases <= {a.get('extra_signed_expected_after')} published it without a signature); "
                               "it is not rebuilt either, so the release is not trusted")

    def _checksums(self) -> None:
        a = self.p.assets
        sums_name = a.get("checksums_file")
        if not sums_name:
            return
        sig_name = a.get("checksums_signature", sums_name + ".asc")
        if sums_name not in self.c.assets:
            if expected(self.c.version, a.get("checksums_expected_after")):
                self.r.add("checksums", Status.FAIL, sums_name, "release has no checksums file")
            else:
                self.r.add("checksums", Status.LEGACY, sums_name, f"releases <= {a.get('checksums_expected_after')} were published without {sums_name}")
            return
        path = self._fetch_asset(sums_name)
        check = self._verify_sig(sums_name, sig_name)
        self.c.sums_signed = bool(check and check.valid)
        try:
            sums = parse_sha256sums(path.read_text())
        except (ChecksumsError, UnicodeDecodeError) as e:
            self.r.add("checksums", Status.FAIL, sums_name, f"malformed: {e}")
            return
        self.c.sums = sums
        for name, sha in sorted(sums.items()):
            api = strip_algo((self.c.assets.get(name) or {}).get("digest"))
            if name not in self.c.assets:
                self.r.add("checksums", Status.FAIL, name, f"listed in {sums_name} but not a release asset")
            elif name in self.c.hashes and self.c.hashes[name] != sha:
                self.r.add("checksums", Status.FAIL, name, f"downloaded {self.c.hashes[name]} != {sums_name} {sha}")
            elif api and api != sha:
                self.r.add("checksums", Status.FAIL, name, f"GitHub digest {api} != {sums_name} {sha}")
            else:
                self.r.add("checksums", Status.PASS, name, f"matches {sums_name}" + (" and GitHub digest" if api else ""))
        for name in self._platform_assets().values():
            if name in self.c.assets and name not in sums:
                self.r.add("checksums", Status.FAIL, name, f"platform package not listed in {sums_name}")

    def _release_attestation(self) -> None:
        if not self.p.attestations.get("release_attestation"):
            return
        if not self.c.release.get("immutable"):
            self.r.add("release-attestation", Status.INFO, self.o.tag, "release is not immutable; GitHub issued no release attestation")
            return
        if not attest.gh_authenticated():
            self.r.add("release-attestation", Status.SKIPPED, self.o.tag, "immutable release, but gh is not authenticated (set GH_TOKEN) so `gh release verify` cannot run")
            return
        try:
            statement = attest.release_attestation(self.p.repo, self.o.tag)
        except RuntimeError as e:
            self.r.add("release-attestation", Status.FAIL, self.o.tag, f"gh release verify failed: {e}")
            return
        if statement is None:
            self.r.add("release-attestation", Status.WARN, self.o.tag, "immutable release without a release attestation")
            return
        commit, subjects = attest.release_attestation_subjects(statement)
        problems = []
        if commit and commit != self.c.commit:
            problems.append(f"attested commit {commit} != tag commit {self.c.commit}")
        for name, sha in self.c.hashes.items():
            if subjects.get(name) != sha:
                problems.append(f"{name}: attested {subjects.get(name)} != downloaded {sha}")
        if problems:
            self.r.add("release-attestation", Status.FAIL, self.o.tag, "; ".join(problems[:5]))
        else:
            self.r.add("release-attestation", Status.PASS, self.o.tag, f"GitHub immutable-release attestation covers the tag commit and {len(self.c.hashes)} downloaded assets")

    def _provenance(self) -> None:
        cfg = self.p.attestations
        if not cfg.get("signer_workflow"):
            return
        legacy = not expected(self.c.version, cfg.get("expected_after"))
        for name in self._platform_assets().values():
            if name not in self.c.downloads:
                continue
            res = attest.verify_provenance(
                self.p.repo, str(self.c.downloads[name]), "sha256:" + self.c.hashes[name],
                cfg["signer_workflow"], cfg.get("predicate_type", "https://slsa.dev/provenance/v1"), self.work / "bundles",
            )
            self._attestation_result("provenance", name, res, legacy)

    def _attestation_result(self, check: str, subject: str, res: attest.AttestationCheck, legacy: bool) -> None:
        if res.outcome == "verified":
            self.r.add(check, Status.PASS, subject, res.message, **res.details)
        elif res.outcome == "missing":
            if legacy:
                self.r.add(check, Status.LEGACY, subject, f"{res.message} (releases <= {self.p.attestations.get('expected_after')} predate build provenance)", **res.details)
            else:
                self.r.add(check, Status.FAIL, subject, res.message, **res.details)
        elif res.outcome == "unavailable":
            self.r.add(check, Status.ERROR, subject, res.message)
        else:
            self.r.add(check, Status.FAIL, subject, res.message, **res.details)

    # -- rebuilds -------------------------------------------------------------------------

    def _template_ctx(self) -> dict[str, Any]:
        c = self.c
        return {
            "project": self.p.name,
            "repo": self.p.repo,
            "tag": self.o.tag,
            "version": c.version,
            "commit": c.commit,
            "sha8": c.commit[:8],
            "source_date_epoch": c.epoch,
            "build_timestamp": _dt.datetime.fromtimestamp(c.epoch, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "work_dir": str(self.work),
            "src_dir": str(self.work / "src"),
            "out_dir": str(self.work / "out"),
            "uid": os.getuid(),
            "gid": os.getgid(),
            "build_image": f"release-verifier-{self.p.name}-pkg:{c.version}-{c.commit[:8]}".lower(),
        }

    def _ensure_checkout(self) -> Path:
        if not self._source_authenticated():
            raise RuntimeError("refusing to check out unauthenticated source for a rebuild")
        if self.c.checkout is None:
            dest = self.work / "src"
            self.c.src.checkout(self.c.commit, dest)
            self.c.checkout = dest
        return self.c.checkout

    def _selected_platforms(self) -> list:
        sel = self.o.platforms
        return [pl for pl in self.p.platforms if sel is None or pl.name in sel]

    def _package_rebuild(self) -> None:
        recipe = self.p.package_rebuild
        assets = self._platform_assets()
        coverage = self.c.coverage["packages"]
        for pl in self._selected_platforms():
            if assets[pl.name] in self.c.downloads:
                coverage[pl.name] = "error"  # until a comparison below says otherwise
        src = self._ensure_checkout()
        ctx = self._template_ctx()
        out = Path(ctx["out_dir"])
        _rmtree(out)
        out.mkdir(parents=True)
        t0 = time.monotonic()
        rebuild.rebuild_packages(recipe, ctx, src, self.log_file, self.o.no_cache)
        self.r.meta.setdefault("rebuild", {})["packages_s"] = round(time.monotonic() - t0, 1)
        # Above the cutoff the archive must be byte-reproducible: a zip whose bytes differ can carry
        # content other unzippers read differently, so "every file matches" is not enough there.
        reproducible = expected(self.c.version, recipe.get("reproducible_archives_expected_after"))
        archive_dir = rebuild.archive_packages(recipe, ctx, self.log_file, self.p.path.parent) if reproducible and "archive" in recipe else None
        for pl in self._selected_platforms():
            name = assets[pl.name]
            if name not in self.c.downloads:
                continue
            with self.stage("package-rebuild", name):
                built = out / pl.build_dir
                if not rebuild.is_plain_dir(built):
                    self.r.add("package-rebuild", Status.ERROR, name, f"rebuild produced no {pl.build_dir}/ directory (missing, or a symlink, which is never followed)")
                    continue
                published = self.c.downloads[name]
                if reproducible:
                    zip_path = archive_dir / name if archive_dir else None
                    rebuilt_sha = sha256_file(zip_path) if zip_path and zip_path.is_file() and not zip_path.is_symlink() else None
                    if rebuilt_sha == self.c.hashes[name]:
                        coverage[pl.name] = "identical"
                        self.r.add("package-rebuild", Status.PASS, name, "rebuilt archive is byte-identical", sha256=rebuilt_sha)
                        continue
                    diff = rebuild.compare_entries(rebuild.zip_entries(published), rebuild.tree_entries(built))
                    if diff.contents_match:
                        coverage[pl.name] = "bytes-differ"
                        self.r.add("package-rebuild", Status.WARN, name,
                                   f"archive bytes differ from the rebuilt archive{'' if rebuilt_sha else ' (the archive step produced none)'} although every file matches; "
                                   f"releases after {recipe.get('reproducible_archives_expected_after')} must be byte-reproducible, so this release is not trusted",
                                   rebuilt_sha256=rebuilt_sha, published_sha256=self.c.hashes[name], diff=diff.to_json())
                    else:
                        coverage[pl.name] = "mismatch"
                        self.r.add("package-rebuild", Status.FAIL, name, "published package differs from the independent rebuild", diff=diff.to_json())
                    continue
                diff = rebuild.compare_entries(rebuild.zip_entries(published), rebuild.tree_entries(built))
                if not diff.contents_match:
                    coverage[pl.name] = "mismatch"
                    self.r.add("package-rebuild", Status.FAIL, name, "published package contents differ from the independent rebuild", diff=diff.to_json())
                    continue
                coverage[pl.name] = "contents-match"
                self.r.add("package-rebuild", Status.PASS, name, f"all {diff.compared} entries match the rebuild file-by-file (legacy archive: releases <= "
                           f"{recipe.get('reproducible_archives_expected_after')} were not archived reproducibly)")
                if diff.mode_mismatch:
                    self.r.add("package-rebuild-modes", Status.WARN, name, "executable bits differ from the rebuild", diff=diff.to_json())

    def _images(self) -> None:
        if not self.p.flavors:
            return
        reg = Registry(self.p.images.get("registry", "docker.io"), self.state.cache_dir)
        cfg = self.p.attestations
        ctx = self._template_ctx()
        legacy_att = not expected(self.c.version, cfg.get("expected_after"))
        reproducible = expected(self.c.version, self.p.images.get("reproducible_expected_after"))
        for flavor in self.p.flavors:
            if self.o.flavors and flavor["name"] not in self.o.flavors:
                continue
            vtag = render(flavor["version_tag"], ctx)
            remote: dict[str, dict[str, Any]] = {}
            for repo in flavor["repos"]:
                key = f"{repo}:{vtag}"
                with self.stage("image", key):
                    # Above the cutoff every configured platform must be published (absent = not
                    # trusted); at or below it, a missing tag or platform is just not covered.
                    gone = "missing" if reproducible else ABSENT
                    try:
                        desc = reg.describe(repo, vtag)
                    except (ValueError, KeyError, TypeError) as e:  # published content the client cannot read
                        self.c.coverage["images"].update({f"{key}@{pl}": "malformed" for pl in flavor["platforms"]})
                        self.r.add("image-index", Status.FAIL, key, f"malformed image index or manifest: {type(e).__name__}: {e}")
                        continue
                    if desc is None:
                        self.c.coverage["images"].update({f"{key}@{pl}": gone for pl in flavor["platforms"]})
                        self.r.add("image", Status.WARN, key, "image tag does not exist" + (
                            f"; releases after {self.p.images.get('reproducible_expected_after')} must publish it, so the release is not trusted" if reproducible else ""))
                        continue
                    self.c.images[key] = {"flavor": flavor["name"], "index_digest": desc["index_digest"], "platforms": desc["platforms"]}
                    for problem in registry.index_problems(desc, flavor["platforms"]):
                        self.r.add("image-index", Status.FAIL, key, problem)
                    for pl in desc["platforms"].keys() - set(flavor["platforms"]):
                        self.c.coverage["images"][f"{key}@{pl}"] = "unexpected"
                    missing = [pl for pl in flavor["platforms"] if pl not in desc["platforms"]]
                    if missing and reproducible:
                        self.r.add("image", Status.WARN, key, f"index lacks {', '.join(missing)}; the release is not trusted")
                    self.c.coverage["images"].update({f"{key}@{pl}": gone for pl in missing})
                    remote[repo] = desc
                    self._image_labels(reg, repo, key, desc, flavor, ctx)
                    if cfg.get("signer_workflow") and flavor.get("attestation_subject"):
                        res = attest.verify_provenance(
                            self.p.repo, f"oci://{flavor['attestation_subject']}@{desc['index_digest']}", desc["index_digest"],
                            cfg["signer_workflow"], cfg.get("predicate_type", "https://slsa.dev/provenance/v1"), self.work / "bundles",
                        )
                        self._attestation_result("image-provenance", key, res, legacy_att)
            if self.o.skip_rebuild or self.o.skip_image_rebuild:
                self.r.add("image-rebuild", Status.SKIPPED, f"{flavor['name']}", "image rebuild skipped by option")
                continue
            if not self._source_authenticated():
                self.r.add("image-rebuild", Status.SKIPPED, f"{flavor['name']}", self._unauthenticated_message())
                continue
            if not remote:
                continue
            for platform in flavor["platforms"]:
                if self.o.image_platforms and platform not in self.o.image_platforms:
                    continue
                with self.stage("image-rebuild", f"{flavor['name']} {platform}"):
                    self.c.coverage["images"].update({f"{repo}:{vtag}@{platform}": "error" for repo, d in remote.items() if platform in d["platforms"]})
                    self._image_rebuild(reg, flavor, platform, ctx, remote, reproducible)

    def _image_labels(self, reg: Registry, repo: str, key: str, desc: dict[str, Any], flavor: dict[str, Any], ctx: dict[str, Any]) -> None:
        want = render(flavor.get("labels", {}), ctx)
        if not want:
            return
        for platform, d in desc["platforms"].items():
            cfg = reg.blob_json(repo, d["config"])
            self._config_docs[d["config"]] = cfg
            labels = (cfg.get("config") or {}).get("Labels") or {}
            bad = {k: labels.get(k) for k, v in want.items() if labels.get(k) != v}
            if bad:
                self.r.add("image-labels", Status.FAIL, f"{key} {platform}", f"labels do not describe this release: {bad}", expected=want)
            else:
                self.r.add("image-labels", Status.PASS, f"{key} {platform}", "revision/version labels match the release commit")

    def _image_rebuild(self, reg: Registry, flavor: dict[str, Any], platform: str, ctx: dict[str, Any], remote: dict[str, Any], reproducible: bool) -> None:
        src = self._ensure_checkout()
        if not self._builder_ready:
            rebuild.ensure_builder(self.o.builder, self.log_file, self.p.images.get("buildkit_image"))
            self._builder_ready = True
        tar = self.work / "images" / f"{flavor['name']}-{platform.replace('/', '-')}.tar"
        t0 = time.monotonic()
        try:
            rebuild.build_image(flavor, platform, ctx, src, self.o.builder, tar, self.log_file, self.o.no_cache)
            built = rebuild.oci_layout_image(tar, platform)
        finally:
            tar.unlink(missing_ok=True)
        self.r.meta.setdefault("rebuild", {})[f"image {flavor['name']} {platform}"] = round(time.monotonic() - t0, 1)
        vtag = render(flavor["version_tag"], ctx)
        for repo, desc in remote.items():
            subject = f"{repo}:{vtag} {platform}"
            pub = desc["platforms"].get(platform)
            if not pub:
                continue
            if pub["config"] == built["config"]:
                self.c.coverage["images"][f"{repo}:{vtag}@{platform}"] = "identical"
                self.r.add("image-rebuild", Status.PASS, subject, f"rebuilt image config digest matches ({built['config']})", manifest_published=pub["manifest"], manifest_rebuilt=built["manifest"])
                continue
            pub_doc = self._config_docs.get(pub["config"]) or reg.blob_json(repo, pub["config"])
            details = {
                "config_published": pub["config"], "config_rebuilt": built["config"],
                "manifest_published": pub["manifest"], "manifest_rebuilt": built["manifest"],
                "explain": rebuild.diff_configs(pub_doc, built["config_doc"]),
            }
            self.c.coverage["images"][f"{repo}:{vtag}@{platform}"] = "mismatch" if reproducible else "legacy-mismatch"
            if reproducible:
                self.r.add("image-rebuild", Status.FAIL, subject, "published image differs from the independent rebuild", **details)
            else:
                self.r.add("image-rebuild", Status.LEGACY, subject,
                           f"config digest differs; releases <= {self.p.images.get('reproducible_expected_after')} were not built reproducibly (no rewrite-timestamp)", **details)

    # -- channels -------------------------------------------------------------------------

    def _channels(self) -> None:
        if not self.p.channels:
            return
        rel = github.summarize_release(self.c.release)
        snap = {"releases": {self.o.tag: rel}, "tags": {self.o.tag: {"commit": self.c.commit}}}
        trusted = {n: h for n, h in self.c.hashes.items() if n in self.c.signed_ok}
        vrec = {"commit": self.c.commit, "assets": trusted, "outcome": "pass", "coverage": {"source": self.c.source}}
        verified = {self.o.tag: vrec}
        vrec["references"] = refs = {}
        for c in self.p.channels:
            if c.get("source_dir") and self._source_authenticated():
                name = c.get("name", c["type"])
                with self.stage("channel-reference", name):
                    refs[name] = self._source_reference(c, expected_assets(self.p, snap, verified, self.o.tag, c["platforms"]))
        self.c.references = {n: {**r, "files": ch.without_texts(r["files"])} if "files" in r else r for n, r in refs.items()}
        coverage = self.c.coverage["channels"]
        for c in self.p.channels:
            name = c.get("name", c["type"])
            coverage[name] = "error"  # until evaluated
            with self.stage("channel", name):
                if rel.get("prerelease"):
                    coverage[name] = "skipped"
                    self.r.add("channel-hash", Status.SKIPPED, name, "pre-releases are not published to distribution channels")
                    continue
                data = self._fetch_channel(c)
                if data is None:
                    coverage[name] = "not-published"
                    continue
                results = evaluate_channel(self.p, snap, verified, c, data)
                self.r.extend(results)
                coverage[name] = _channel_coverage(results)

    def _source_reference(self, c: dict[str, Any], exp: dict[str, dict[str, str]]) -> dict[str, Any]:
        """What the channel's publishing job builds from the authenticated tree at the tag (read from
        git objects; nothing is run), with the verified URLs and hashes substituted."""
        unverified = [p for p in c["platforms"] if (exp.get(p) or {}).get("source") != "verified"]
        if unverified:
            return {"unavailable": f"no verified asset hash for {', '.join(unverified)}"}
        root = c["source_dir"].rstrip("/")
        tree = ch.tar_tree(self.c.src.archive(self.c.commit, root), root + "/")
        return {"commit": self.c.commit, "files": ch.ppa_reference(tree, c.get("file", "debian/postinst"), [exp[p] for p in c["platforms"]])}

    def _fetch_channel(self, c: dict[str, Any]) -> Any:
        name = c.get("name", c["type"])
        v = self.c.version
        if c["type"] == "homebrew":
            data = ch.fetch_homebrew(c)
            if data.get("version") != v:
                self.r.add("channel-hash", Status.SKIPPED, name, f"formula is at version {data.get('version')}, not {v}")
                return None
            return data
        if c["type"] == "winget":
            m = ch.fetch_winget(c, v)
            if m is None:
                self.r.add("channel-hash", Status.SKIPPED, name, f"no winget manifest for {v} (yet)")
                return None
            return {"listed": None, "manifests": {v: m}}
        if c["type"] == "ppa":
            key = None
            if c.get("dsc_signing_fingerprint"):
                same = c["dsc_signing_fingerprint"].replace(" ", "").upper() == self.p.fingerprint
                key, _ = fetch_pinned_key(c["dsc_signing_fingerprint"], self.p.key_file() if same else None, c.get("key_urls"), self.state.cache_dir)
            data = ch.fetch_ppa(c, {v}, key)
            if v not in data["sources"]:
                self.r.add("channel-hash", Status.SKIPPED, name, f"{v} is not published on the PPA")
                return None
            # This release only; `watch` checks everything else the PPA publishes.
            return {"sources": {v: data["sources"][v]}, "other_packages": {}}
        raise ValueError(f"unknown channel type {c['type']}")

    def _cleanup(self) -> None:
        if self.o.keep_work:
            return
        if self.c.src and self.c.checkout:
            self.c.src.remove_checkout(self.c.checkout)
        for d in ("out", "archive", "images", "downloads", "bundles"):
            _rmtree(self.work / d)


def _is_version(v: Any) -> bool:
    try:
        Version(v)
        return True
    except (TypeError, ValueError, AttributeError):
        return False


def _rmtree(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)
    if path.exists():
        log.warning("could not fully remove %s (root-owned files from a failed build?)", path)


def _channel_coverage(results: list[Result]) -> str:
    """``verified``: hashes and executable content match trusted content; ``hash-only``: the content
    was not compared (no trusted reference, or the channel has no content check)."""
    statuses = {r.status for r in results}
    if Status.FAIL in statuses:
        return "mismatch"
    if Status.ERROR in statuses:
        return "error"
    if Status.WARN in statuses:
        return "incomplete"
    content = [r for r in results if r.check == "channel-content"]
    return "verified" if content and all(r.status is Status.PASS for r in content) else "hash-only"


def run(project: Project, state: State, opts: Options) -> Report:
    return Verifier(project, state, opts).run()
