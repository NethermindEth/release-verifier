"""State diffing and single-snapshot evaluation (watch)."""

import copy
import unittest
from pathlib import Path
from unittest import mock

from release_verifier import channels, watch
from release_verifier.config import PROJECTS_DIR, Project, load
from release_verifier.net import HttpError
from release_verifier.results import Status

FIX = Path(__file__).parent / "fixtures"
C220 = "1d2aff00ccee8df1ffabc142ee8ea61b3760754e"
C230 = "abcdef1234567890abcdef1234567890abcdef12"
REPO_DL = "https://github.com/NethermindEth/nethermind/releases/download"
H = {p: (str(i) * 64) for i, p in enumerate(["linux-arm64", "linux-x64", "macos-arm64", "macos-x64", "windows-x64"], 1)}


def release(tag, commit, rid, published="2026-10-16T16:26:20Z", updated="2026-10-16T15:44:57Z"):
    assets = {}
    for i, (p, h) in enumerate(H.items()):
        name = f"nethermind-{tag}-{commit[:8]}-{p}.zip"
        assets[name] = {"id": rid * 100 + i, "digest": f"sha256:{h}", "size": 1000 + i, "updated_at": updated}
    return {"id": rid, "tag": tag, "draft": False, "prerelease": False, "immutable": True, "published_at": published, "assets": assets}


def image(digest, version, flavor="default"):
    return {"index_digest": digest, "flavor": flavor, "version": version,
            "platforms": {"linux/amd64": {"manifest": "sha256:m1", "config": "sha256:c1"}}}


def asset_url(p):
    return f"{REPO_DL}/2.2.0/nethermind-2.2.0-1d2aff00-{p}.zip"


def formula():
    """The 2.2.0 formula as publish-packages.yml writes it, with this module's fake hashes."""
    template = (PROJECTS_DIR / "templates" / "nethermind" / "homebrew.rb").read_text()
    return channels.render_template(template, "2.2.0", {p: {"url": asset_url(p), "sha256": H[p]} for p in ("macos-x64", "macos-arm64")})


def ppa_source():
    """(reference built from the 2.2.0 source tree, published source package) with the fake hashes."""
    trusted = channels.tar_tree((FIX / "ppa-source-2.2.0.tar.xz").read_bytes(), "scripts/build/ppa/")
    ref = channels.ppa_reference(trusted, "debian/postinst", [{"url": asset_url(p), "sha256": H[p]} for p in ("linux-arm64", "linux-x64")])
    published = {**ref, "debian/changelog": channels.tar_tree((FIX / "nethermind_2.2.0.tar.xz").read_bytes())["debian/changelog"]}
    return ref, published


def full_coverage(packages="identical", images="identical"):
    """Coverage of a complete `verify` run of 2.2.0 (windows-arm64 was not published)."""
    return {
        "source": "pinned",
        "packages": {**{p: packages for p in H}, "windows-arm64": "absent"},
        "images": {f"nethermind/nethermind:2.2.0{s}@{pl}": images for s in ("", "-chiseled") for pl in ("linux/amd64", "linux/arm64")},
        "channels": {},
    }


def snapshot():
    return {
        "taken_at": "2026-10-19T00:00:00Z",
        "errors": {},
        "tags": {"2.2.0": {"object": C220, "type": "commit", "commit": C220}},
        "releases": {"2.2.0": release("2.2.0", C220, 1)},
        "images": {
            "nethermind/nethermind:2.2.0": image("sha256:idx220", "2.2.0"),
            "nethermind/nethermind:latest": image("sha256:idx220", None),
        },
        "channels": {
            "homebrew": {"version": "2.2.0", "text": formula(), "entries": [
                {"url": asset_url("macos-x64"), "sha256": H["macos-x64"]},
                {"url": asset_url("macos-arm64"), "sha256": H["macos-arm64"]},
            ]},
        },
    }


def by_check(results, check):
    return [r for r in results if r.check == check]


class DiffTest(unittest.TestCase):
    def setUp(self):
        self.p = load("nethermind")
        self.prev = snapshot()

    def diff(self, cur, verified=None):
        return watch.diff(self.p, self.prev, cur, verified or {})

    def test_no_change_no_findings(self):
        self.assertEqual(self.diff(copy.deepcopy(self.prev)), [])

    def test_tag_moved_and_deleted(self):
        cur = copy.deepcopy(self.prev)
        cur["tags"]["2.2.0"] = {"object": "f" * 40, "type": "tag", "commit": "e" * 40}
        [r] = self.diff(cur)
        self.assertEqual((r.check, r.status), ("tag", Status.FAIL))
        self.assertIn("moved", r.message)
        del cur["tags"]["2.2.0"]
        [r] = self.diff(cur)
        self.assertEqual(r.status, Status.FAIL)
        self.assertIn("deleted", r.message)

    def test_tag_diff_suppressed_when_collection_failed(self):
        cur = copy.deepcopy(self.prev)
        cur["tags"] = {}
        cur["errors"] = {"tags": "timeout"}
        self.assertEqual(self.diff(cur), [])

    def test_asset_replaced_added_removed(self):
        cur = copy.deepcopy(self.prev)
        assets = cur["releases"]["2.2.0"]["assets"]
        x64 = "nethermind-2.2.0-1d2aff00-linux-x64.zip"
        assets[x64] = {**assets[x64], "digest": "sha256:" + "9" * 64, "id": 999}
        del assets["nethermind-2.2.0-1d2aff00-macos-x64.zip"]
        assets["nethermind-2.2.0-1d2aff00-windows-arm64.zip"] = {"id": 5, "digest": "sha256:" + "8" * 64, "size": 1, "updated_at": "x"}
        rs = by_check(self.diff(cur), "release-asset")
        self.assertEqual(sorted(r.message for r in rs),
                         ["asset added after publication", "asset removed after publication", "asset replaced after publication"])
        self.assertTrue(all(r.status is Status.FAIL for r in rs))

    def test_release_deleted_and_recreated(self):
        cur = copy.deepcopy(self.prev)
        cur["releases"]["2.2.0"]["id"] = 2
        [r] = by_check(self.diff(cur), "release")
        self.assertEqual(r.status, Status.FAIL)
        del cur["releases"]["2.2.0"]
        [r] = by_check(self.diff(cur), "release")
        self.assertIn("disappeared", r.message)

    def test_draft_changes_are_not_compromise(self):
        prev = snapshot()
        prev["releases"]["2.2.0"]["draft"] = True
        cur = copy.deepcopy(prev)
        cur["releases"]["2.2.0"]["assets"].popitem()
        cur["releases"]["2.2.0"]["draft"] = False
        rs = watch.diff(self.p, prev, cur, {})
        self.assertTrue(rs)
        self.assertFalse([r for r in rs if r.status is Status.FAIL])

    def test_new_release_needs_verify(self):
        cur = copy.deepcopy(self.prev)
        cur["releases"]["2.3.0"] = release("2.3.0", C230, 3)
        [r] = by_check(self.diff(cur), "release")
        self.assertEqual(r.status, Status.WARN)
        [r] = by_check(self.diff(cur, {"2.3.0": {"outcome": "pass"}}), "release")
        self.assertEqual(r.status, Status.INFO)

    def test_version_image_repointed_vs_latest_moved(self):
        cur = copy.deepcopy(self.prev)
        cur["images"]["nethermind/nethermind:2.2.0"]["index_digest"] = "sha256:evil"
        cur["images"]["nethermind/nethermind:latest"]["index_digest"] = "sha256:new"
        rs = {r.subject: r for r in by_check(self.diff(cur), "image-tag")}
        self.assertEqual(rs["nethermind/nethermind:2.2.0"].status, Status.FAIL)
        self.assertEqual(rs["nethermind/nethermind:latest"].status, Status.INFO)

    def test_image_tag_out_of_window_is_ignored(self):
        cur = copy.deepcopy(self.prev)
        del cur["releases"]["2.2.0"]
        del cur["images"]["nethermind/nethermind:2.2.0"]
        self.assertEqual(by_check(self.diff(cur), "image-tag"), [])


def api_release(summary):
    """GitHub API form of a ``release()`` summary."""
    return {**{k: v for k, v in summary.items() if k not in ("tag", "assets")}, "tag_name": summary["tag"],
            "assets": [{"name": n, **a} for n, a in summary["assets"].items()]}


class WindowTest(unittest.TestCase):
    """A tracked release that ages out of the watch window is not a deletion (one-release window)."""

    def setUp(self):
        base = load("nethermind")
        raw = copy.deepcopy(base.raw)
        raw["channels"], raw["images"]["flavors"] = [], []
        raw["watch"]["release_window"] = 1
        self.p = Project(base.path, raw)
        self.prev = snapshot()
        self.old = self.prev["releases"]["2.2.0"]
        self.new = release("2.3.0", C230, 3, published="2026-11-01T00:00:00Z", updated="2026-11-01T00:00:00Z")
        tags = {**self.prev["tags"], "2.3.0": {"object": C230, "type": "commit", "commit": C230}}
        for p in (mock.patch.object(watch, "_collect_tags", return_value=tags),
                  mock.patch.object(watch.github, "tree_entry", return_value=None),
                  mock.patch.object(watch.github, "releases", return_value=[api_release(self.new)])):
            p.start()
            self.addCleanup(p.stop)

    def run_watch(self, by_tag):
        with mock.patch.object(watch.github, "release_by_tag", side_effect=by_tag) as lookup:
            cur = watch.collect(self.p, None, self.prev)
        lookup.assert_called_once_with(self.p.repo, "2.2.0")
        return cur, [r for r in watch.diff(self.p, self.prev, cur, {}) if r.check == "release" and r.subject == "2.2.0"]

    def test_evicted_unverified_release_warns(self):
        cur, [r] = self.run_watch(lambda repo, tag: api_release(self.old))
        self.assertEqual(list(cur["releases"]), ["2.3.0"])
        self.assertEqual(cur["evicted"], ["2.2.0"])
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("left the watched window", r.message)

    def test_deleted_release_still_fails(self):
        cur, [r] = self.run_watch(lambda repo, tag: None)
        self.assertEqual(cur["evicted"], [])
        self.assertEqual((r.status, r.message), (Status.FAIL, "published release disappeared"))

    def test_lookup_error_is_a_collection_error(self):
        def fail(repo, tag):
            raise HttpError("https://api.github.com/x", 502)
        cur, rs = self.run_watch(fail)
        self.assertIn("releases", cur["errors"])
        self.assertEqual(cur["releases"], self.prev["releases"])  # carried forward
        self.assertEqual(rs, [])
        self.assertEqual([r.status for r in watch.evaluate(self.p, cur, {}) if r.check == "collect"], [Status.ERROR])

    def test_changed_release_outside_the_window_is_still_diffed(self):
        changed = copy.deepcopy(self.old)
        changed["assets"]["evil.zip"] = {"id": 9, "digest": "sha256:" + "e" * 64, "size": 1, "updated_at": "2026-11-02T00:00:00Z"}
        cur, _ = self.run_watch(lambda repo, tag: api_release(changed))
        self.assertEqual(cur["evicted"], [])
        [r] = [r for r in watch.diff(self.p, self.prev, cur, {}) if r.subject == "2.2.0/evil.zip"]
        self.assertEqual((r.status, r.message), (Status.FAIL, "asset added after publication"))



class EvaluateTest(unittest.TestCase):
    def setUp(self):
        self.p = load("nethermind")
        self.snap = snapshot()

    def verified(self, outcome="pass", digest="sha256:idx220", assets=None, coverage=None):
        return {"2.2.0": {"version": "2.2.0", "commit": C220, "outcome": outcome, "coverage": coverage or full_coverage(),
                          "assets": assets or {}, "images": {"nethermind/nethermind:2.2.0": {"index_digest": digest}}}}

    def latest(self, results):
        [r] = by_check(results, "latest-tag")
        return r

    def test_latest_requires_verified_release(self):
        self.assertEqual(self.latest(watch.evaluate(self.p, self.snap, {})).status, Status.WARN)
        self.assertEqual(self.latest(watch.evaluate(self.p, self.snap, self.verified())).status, Status.PASS)
        self.assertEqual(self.latest(watch.evaluate(self.p, self.snap, self.verified("fail"))).status, Status.FAIL)
        self.assertEqual(self.latest(watch.evaluate(self.p, self.snap, self.verified("inconclusive"))).status, Status.WARN)

    def test_latest_requires_full_coverage(self):
        # The review's reproduction: a passing record whose rebuilds were skipped must not make `latest` PASS.
        skipped = full_coverage(packages="skipped", images="skipped")
        r = self.latest(watch.evaluate(self.p, self.snap, self.verified(coverage=skipped)))
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("packages skipped: linux-arm64, linux-x64, macos-arm64 (+2 more)", r.message)
        partial = full_coverage()
        partial["packages"]["linux-arm64"] = "skipped"
        partial["images"]["nethermind/nethermind:2.2.0@linux/arm64"] = "legacy-mismatch"
        r = self.latest(watch.evaluate(self.p, self.snap, self.verified(coverage=partial)))
        self.assertEqual(r.status, Status.WARN)
        self.assertEqual(r.details["missing_coverage"], ["packages skipped: linux-arm64", "images legacy-mismatch: nethermind/nethermind:2.2.0@linux/arm64"])
        unauthenticated = {**full_coverage(), "source": "unauthenticated"}
        self.assertIn("source unauthenticated", self.latest(watch.evaluate(self.p, self.snap, self.verified(coverage=unauthenticated))).message)

    def test_records_without_coverage_are_untrusted(self):
        old = self.verified()
        del old["2.2.0"]["coverage"]
        old["2.2.0"]["rebuilt"] = {"packages": True, "images": True}
        r = self.latest(watch.evaluate(self.p, self.snap, old))
        self.assertEqual(r.status, Status.WARN)
        self.assertIn("predates coverage tracking", r.message)

    def test_latest_to_unknown_digest_is_compromise(self):
        self.snap["images"]["nethermind/nethermind:latest"]["index_digest"] = "sha256:unknown"
        self.assertEqual(self.latest(watch.evaluate(self.p, self.snap, self.verified())).status, Status.FAIL)

    def test_version_tag_differs_from_verified(self):
        rs = by_check(watch.evaluate(self.p, self.snap, self.verified(digest="sha256:other")), "image-tag")
        self.assertEqual([r.status for r in rs], [Status.FAIL])

    def test_verified_hashes_are_authoritative(self):
        name = "nethermind-2.2.0-1d2aff00-linux-x64.zip"
        rs = by_check(watch.evaluate(self.p, self.snap, self.verified(assets={name: "f" * 64})), "verified-asset")
        self.assertEqual([r.status for r in rs], [Status.FAIL])

    def test_tag_moved_since_verification(self):
        self.snap["tags"]["2.2.0"]["commit"] = "e" * 40
        rs = by_check(watch.evaluate(self.p, self.snap, self.verified()), "verified-tag")
        self.assertEqual([r.status for r in rs], [Status.FAIL])

    def test_homebrew_hash_matches_release(self):
        rs = by_check(watch.evaluate(self.p, self.snap, {}), "channel-hash")
        self.assertEqual([r.status for r in rs], [Status.PASS, Status.PASS])

    def test_homebrew_hash_mismatch_and_foreign_url(self):
        e = self.snap["channels"]["homebrew"]["entries"]
        e[0]["sha256"] = "0" * 64
        e[1]["url"] = "https://evil.example/nethermind-2.2.0-1d2aff00-macos-arm64.zip"
        rs = by_check(watch.evaluate(self.p, self.snap, {}), "channel-hash")
        self.assertEqual([r.status for r in rs], [Status.FAIL, Status.FAIL])
        self.assertIn("not the release download URL", rs[1].message)

    def test_channel_pointing_at_other_release_asset(self):
        e = self.snap["channels"]["homebrew"]["entries"]
        e[0]["url"] = f"{REPO_DL}/2.2.0/nethermind-2.2.0-deadbeef-macos-x64.zip"
        rs = by_check(watch.evaluate(self.p, self.snap, {}), "channel-hash")
        self.assertEqual(rs[0].status, Status.FAIL)
        self.assertIn("unknown asset", rs[0].message)

    def test_channel_missing_platform_warns(self):
        self.snap["channels"]["homebrew"]["entries"].pop()
        rs = by_check(watch.evaluate(self.p, self.snap, {}), "channel-hash")
        self.assertEqual(sorted(r.status.value for r in rs), ["pass", "warn"])

    def test_asset_modified_after_publication(self):
        name = "nethermind-2.2.0-1d2aff00-linux-x64.zip"
        self.snap["releases"]["2.2.0"]["assets"][name]["updated_at"] = "2026-10-17T00:00:00Z"
        [r] = by_check(watch.evaluate(self.p, self.snap, {}), "asset-after-publication")
        self.assertEqual(r.status, Status.WARN)

    def test_release_without_tag(self):
        del self.snap["tags"]["2.2.0"]
        [r] = by_check(watch.evaluate(self.p, self.snap, {}), "release-tag")
        self.assertEqual(r.status, Status.FAIL)

    def test_collection_errors_are_tool_errors(self):
        self.snap["errors"] = {"images": "registry down"}
        [r] = by_check(watch.evaluate(self.p, self.snap, {}), "collect")
        self.assertEqual(r.status, Status.ERROR)

    def test_ppa_signature_and_integrity(self):
        self.snap["channels"]["ppa"] = {"sources": {"2.2.0": {
            "dsc_signature": "wrong-key", "tarball_matches_dsc": False, "series": ["jammy"],
            "entries": [{"url": f"{REPO_DL}/2.2.0/nethermind-2.2.0-1d2aff00-linux-x64.zip", "sha256": H["linux-x64"]},
                        {"url": f"{REPO_DL}/2.2.0/nethermind-2.2.0-1d2aff00-linux-arm64.zip", "sha256": H["linux-arm64"]}],
        }}}
        rs = watch.evaluate(self.p, self.snap, self.verified())
        self.assertEqual(by_check(rs, "ppa-upload-signature")[0].status, Status.FAIL)
        self.assertEqual(by_check(rs, "ppa-source-integrity")[0].status, Status.FAIL)
        self.assertEqual({r.status for r in by_check(rs, "channel-hash") if r.subject.startswith("ppa")}, {Status.PASS})


class ChannelContentTest(unittest.TestCase):
    """watch re-checks executable channel content on every run."""

    def setUp(self):
        self.p = load("nethermind")
        self.snap = snapshot()
        self.ref, published = ppa_source()
        self.snap["channels"]["ppa"] = {"sources": {"2.2.0": {
            "dsc_signature": "valid", "tarball_matches_dsc": True, "series": ["jammy", "noble", "resolute"],
            "entries": channels.parse_postinst(published["debian/postinst"]["text"]),
            "trees": {"nethermind_2.2.0.tar.xz": published},
        }}}

    def verified(self, source="pinned"):
        return {"2.2.0": {"version": "2.2.0", "commit": C220, "outcome": "pass", "assets": {}, "images": {}, "coverage": {**full_coverage(), "source": source},
                          "references": {"ppa": {"commit": C220, "files": channels.without_texts(self.ref)}}}}

    def content(self, verified):
        return {r.subject.split("@")[0]: r for r in by_check(watch.evaluate(self.p, self.snap, verified), "channel-content")}

    def test_untampered_channels_pass(self):
        rs = self.content(self.verified())
        self.assertEqual({k: r.status for k, r in rs.items()}, {"homebrew": Status.PASS, "ppa": Status.PASS})

    def test_formula_drift_from_pinned_template_fails(self):
        hb = self.snap["channels"]["homebrew"]
        hb["text"] = hb["text"].replace("  test do", "  post_install do\n    system \"id\"\n  end\n\n  test do")
        rs = self.content(self.verified())
        self.assertEqual(rs["homebrew"].status, Status.FAIL)
        self.assertEqual({r.status for r in by_check(watch.evaluate(self.p, self.snap, {}), "channel-hash") if r.subject.startswith("homebrew")}, {Status.PASS})

    def test_postinst_with_extra_command_fails(self):
        tree = self.snap["channels"]["ppa"]["sources"]["2.2.0"]["trees"]["nethermind_2.2.0.tar.xz"]
        text = tree["debian/postinst"]["text"].replace("exit 0", "id\nexit 0")
        tree["debian/postinst"] = {**channels._file_entry(text)}
        rs = self.content(self.verified())
        self.assertEqual(rs["ppa"].status, Status.FAIL)
        self.assertIn("debian/postinst changed", rs["ppa"].message)

    def test_ppa_content_needs_an_authenticated_reference(self):
        for verified, reason in [(self.verified("unauthenticated"), "not authenticated")]:
            with self.subTest(reason=reason):
                r = self.content(verified)["ppa"]
                self.assertEqual(r.status, Status.SKIPPED)
                self.assertIn(reason, r.message)


if __name__ == "__main__":
    unittest.main()
