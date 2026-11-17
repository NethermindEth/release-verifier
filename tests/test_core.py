"""Finding classification, versions, config validation, signatures, archive and OCI comparison."""

import copy
import hashlib
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from release_verifier import alerts, rebuild
from release_verifier.config import PROJECTS_DIR, ConfigError, render, validate
from release_verifier.gpg import Keyring, parse_status
from release_verifier.results import Report, Status, exit_code, Result
from release_verifier.versions import Version, expected

PIN = "AD1279765093C6759CD8A40024A774616F1E617E"
SUB = "61314CD0F6BC06636C6389F7F69B4DBCDCA8E1D7"


def R(status):
    return Result("c", status, "s", "m")


class ClassificationTest(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(exit_code([]), 0)
        self.assertEqual(exit_code([R(s) for s in (Status.PASS, Status.LEGACY, Status.SKIPPED, Status.INFO, Status.WARN)]), 0)
        self.assertEqual(exit_code([R(Status.PASS), R(Status.ERROR)]), 2)
        self.assertEqual(exit_code([R(Status.ERROR), R(Status.FAIL)]), 1)

    def test_summary_orders_by_severity_and_hides_passes(self):
        rep = Report("verify", "nethermind", "2.2.0")
        rep.add("a", Status.PASS, "x", "ok")
        rep.add("b", Status.LEGACY, "x", "old")
        rep.add("c", Status.FAIL, "x", "bad")
        lines = rep.summary().splitlines()
        self.assertIn("COMPROMISE", lines[0])
        self.assertTrue(lines[2].startswith("[FAIL"))
        self.assertTrue(lines[3].startswith("[LEGACY"))
        self.assertEqual(len(lines), 4)
        self.assertEqual(json.loads(rep.dumps())["exit_code"], 1)


class VersionTest(unittest.TestCase):
    def test_ordering(self):
        order = ["1.36.2", "2.2.0", "2.2.1-rc.1", "2.2.1-rc.2", "2.2.1-rc.10", "2.2.1", "2.10.0"]
        self.assertEqual(sorted(order, key=Version), order)
        self.assertTrue(Version("2.3.0-alpha") < Version("2.3.0-alpha.1") < Version("2.3.0-beta"))
        self.assertEqual(Version("v2.2.0"), Version("2.2.0"))

    def test_expected_after(self):
        self.assertFalse(expected("2.2.0", "2.2.0"))
        self.assertFalse(expected("1.39.3", "2.2.0"))
        self.assertTrue(expected("2.2.1-rc.1", "2.2.0"))
        self.assertTrue(expected("2.3.0", "2.2.0"))
        self.assertTrue(expected("0.1.0", None))


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads((PROJECTS_DIR / "nethermind.json").read_text())

    def test_bundled_config_is_valid(self):
        validate(self.raw)

    def test_rejections(self):
        cases = [
            (lambda r: r["tags"].update(pattern=r"^\d+$"), "named group"),
            (lambda r: r["signing_key"].update(fingerprint="24A774616F1E617E"), "40-hex"),
            (lambda r: r["assets"].update(template="x.zip"), "{platform}"),
            (lambda r: r["channels"].append({"type": "snap", "platforms": []}), "unknown type"),
            (lambda r: r["channels"].append(copy.deepcopy(r["channels"][0])), "duplicate"),
            (lambda r: r["package_rebuild"]["steps"].append({"run": "docker build ."}), "argv list"),
            (lambda r: r["tags"]["trusted_commits"].update({"2.1.0": "1d2aff00"}), "trusted_commits"),
            (lambda r: r.update(releases={"ignore_tag_patterns": ["^bootnode-("]}), "ignore_tag_patterns"),
            (lambda r: r.update(releases={"ignore_tag_patterns": "^bootnode-"}), "ignore_tag_patterns"),
        ]
        for mutate, msg in cases:
            raw = copy.deepcopy(self.raw)
            mutate(raw)
            with self.subTest(msg=msg), self.assertRaisesRegex(ConfigError, msg):
                validate(raw)

    def test_render_is_strict(self):
        self.assertEqual(render(["a={commit}", {"k": "{sha8}"}], {"commit": "abc", "sha8": "ab"}), ["a=abc", {"k": "ab"}])
        with self.assertRaisesRegex(ConfigError, "unknown template variable"):
            render("{nope}", {})


class GpgStatusTest(unittest.TestCase):
    def status(self, *lines):
        return "\n".join("[GNUPG:] " + l for l in lines)

    def validsig(self, primary=PIN):
        return f"VALIDSIG {SUB} 2026-10-16 1792170000 0 4 0 1 10 00 {primary}"

    def test_valid_by_subkey_with_pinned_primary(self):
        c = parse_status(self.status("NEWSIG", "GOODSIG 24A774616F1E617E Nethermind", self.validsig(), "TRUST_UNDEFINED 0 pgp"), PIN)
        self.assertEqual((c.outcome, c.signer_primary, c.signer_key), ("valid", PIN, SUB))

    def test_wrong_key(self):
        c = parse_status(self.status("GOODSIG 1111 Mallory", self.validsig("B" * 40)), PIN)
        self.assertEqual(c.outcome, "wrong-key")

    def test_bad_expired_revoked_missing(self):
        self.assertEqual(parse_status(self.status("BADSIG 24A774616F1E617E Nethermind"), PIN).outcome, "bad")
        self.assertEqual(parse_status(self.status("EXPKEYSIG 24A7 N", self.validsig()), PIN).outcome, "expired-key")
        self.assertEqual(parse_status(self.status("REVKEYSIG 24A7 N", self.validsig()), PIN).outcome, "revoked-key")
        self.assertEqual(parse_status(self.status("ERRSIG 24A7 1 10 00 1 9", "NO_PUBKEY 24A7"), PIN).outcome, "no-key")
        self.assertEqual(parse_status("", PIN).outcome, "error")


@unittest.skipUnless(shutil.which("gpg"), "gpg not installed")
class GpgRoundTripTest(unittest.TestCase):
    """Real signatures from a throwaway key: the pin, not keyring membership, decides validity."""

    @classmethod
    def setUpClass(cls):
        cls.signer = Keyring()
        p = cls.signer._gpg("--passphrase", "", "--quick-gen-key", "Test <t@example.invalid>", "ed25519", "sign", "never")
        if p.returncode != 0:
            raise unittest.SkipTest(f"cannot generate key: {p.stderr.decode()}")
        [cls.fpr] = cls.signer.fingerprints()
        cls.pub = cls.signer._gpg("--armor", "--export", cls.fpr).stdout
        cls.tmp = Path(tempfile.mkdtemp())
        cls.data = cls.tmp / "SHA256SUMS"
        cls.data.write_text("x\n")
        cls.signer._gpg("--armor", "--detach-sign", "-o", str(cls.tmp / "SHA256SUMS.asc"), str(cls.data))

    @classmethod
    def tearDownClass(cls):
        cls.signer.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_verify(self):
        with Keyring() as kr:
            kr.import_key_data(self.pub)
            self.assertEqual(kr.verify_detached(self.tmp / "SHA256SUMS.asc", self.data, self.fpr).outcome, "valid")
            self.assertEqual(kr.verify_detached(self.tmp / "SHA256SUMS.asc", self.data, PIN).outcome, "wrong-key")
            tampered = self.tmp / "tampered"
            tampered.write_text("y\n")
            self.assertEqual(kr.verify_detached(self.tmp / "SHA256SUMS.asc", tampered, self.fpr).outcome, "bad")
        with Keyring() as empty:
            self.assertEqual(empty.verify_detached(self.tmp / "SHA256SUMS.asc", self.data, self.fpr).outcome, "no-key")


class ArchiveCompareTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.tree = self.tmp / "linux-x64"
        (self.tree / "plugins").mkdir(parents=True)
        (self.tree / "nethermind").write_bytes(b"\x7fELF")
        os.chmod(self.tree / "nethermind", 0o755)
        (self.tree / "plugins" / "a.dll").write_bytes(b"dll")
        try:
            os.symlink("nethermind", self.tree / "Nethermind.Runner")
        except (OSError, NotImplementedError) as e:  # e.g. Windows without the symlink privilege
            self.skipTest(f"cannot create symlinks here ({e}); release archives contain them and the verifier targets Linux")

    def make_zip(self, path, overrides=None, with_dirs=True):
        """Archive like `zip -ry` does: unix modes, symlinks stored as their target."""
        overrides = overrides or {}
        with zipfile.ZipFile(path, "w") as z:
            for name, e in sorted(rebuild.tree_entries(self.tree).items()):
                if e.kind == "dir" and not with_dirs:
                    continue
                zi = zipfile.ZipInfo(name + ("/" if e.kind == "dir" else ""))
                zi.create_system = 3
                full = self.tree / name
                zi.external_attr = full.lstat().st_mode << 16
                if e.kind == "symlink":
                    data = os.readlink(full).encode()
                elif e.kind == "dir":
                    data = b""
                else:
                    data = full.read_bytes()
                z.writestr(zi, overrides.get(name, data))
        return path

    def compare(self, zip_path):
        return rebuild.compare_entries(rebuild.zip_entries(zip_path), rebuild.tree_entries(self.tree))

    def test_identical(self):
        d = self.compare(self.make_zip(self.tmp / "ok.zip"))
        self.assertTrue(d.contents_match)
        self.assertEqual(d.compared, 4)

    def test_content_and_symlink_tampering(self):
        d = self.compare(self.make_zip(self.tmp / "bad.zip", {"plugins/a.dll": b"evil", "Nethermind.Runner": b"/tmp/evil"}))
        self.assertFalse(d.contents_match)
        self.assertEqual(d.content_mismatch, ["Nethermind.Runner", "plugins/a.dll"])

    def test_missing_and_extra(self):
        z = self.make_zip(self.tmp / "z.zip", with_dirs=False)
        (self.tree / "plugins" / "b.dll").write_bytes(b"new")
        d = self.compare(z)
        self.assertEqual(d.extra_in_rebuild, ["plugins/b.dll"])
        self.assertEqual(d.compared, 3)  # directories ignored when the zip has none

    def test_exec_bit_reported_separately(self):
        z = self.make_zip(self.tmp / "z.zip")
        os.chmod(self.tree / "nethermind", 0o644)
        d = self.compare(z)
        self.assertTrue(d.contents_match)
        self.assertEqual(len(d.mode_mismatch), 1)


class RunLoggedTest(unittest.TestCase):
    def test_failure_reports_the_log_tail(self):
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "logs" / "build.log"
            script = "import sys; sys.stdout.write('x' * 5000 + 'END'); sys.exit(3)"
            with self.assertRaises(rebuild.RebuildError) as cm:
                rebuild.run_logged([sys.executable, "-c", script], Path(td), log, name="step")
            msg = str(cm.exception)
            self.assertIn("step 'step' exited 3", msg)
            tail = msg.split("log tail:\n", 1)[1]
            self.assertEqual(tail, log.read_bytes()[-rebuild.LOG_TAIL:].decode())
            self.assertTrue(tail.endswith("END"))
            self.assertEqual(rebuild.log_tail(log, 10 ** 9), log.read_text())  # shorter than the limit


class OciLayoutTest(unittest.TestCase):
    def test_reads_config_digest_through_nested_index(self):
        blobs = {}

        def add(obj):
            data = json.dumps(obj).encode()
            d = "sha256:" + hashlib.sha256(data).hexdigest()
            blobs[d] = data
            return d, len(data)

        cfg_d, cfg_n = add({"architecture": "amd64", "os": "linux", "rootfs": {"type": "layers", "diff_ids": ["sha256:l1"]}})
        man_d, man_n = add({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "config": {"digest": cfg_d, "size": cfg_n}, "layers": [{"digest": "sha256:z1"}]})
        idx_d, idx_n = add({"schemaVersion": 2, "manifests": [
            {"digest": man_d, "size": man_n, "platform": {"os": "linux", "architecture": "amd64"}},
        ]})
        top = json.dumps({"schemaVersion": 2, "manifests": [{"digest": idx_d, "size": idx_n}]}).encode()
        with tempfile.TemporaryDirectory() as td:
            tar_path = Path(td) / "img.tar"
            with tarfile.open(tar_path, "w") as tf:
                for name, data in [("index.json", top)] + [(f"blobs/sha256/{d[7:]}", b) for d, b in blobs.items()]:
                    ti = tarfile.TarInfo(name)
                    ti.size = len(data)
                    tf.addfile(ti, io.BytesIO(data))
            img = rebuild.oci_layout_image(tar_path, "linux/amd64")
        self.assertEqual((img["manifest"], img["config"], img["layers"]), (man_d, cfg_d, ["sha256:z1"]))

    def test_diff_configs_explains_layers_and_labels(self):
        a = {"rootfs": {"diff_ids": ["sha256:1", "sha256:2"]}, "config": {"Labels": {"v": "1"}}, "created": "t1"}
        b = {"rootfs": {"diff_ids": ["sha256:1", "sha256:3"]}, "config": {"Labels": {"v": "2"}}, "created": "t1"}
        self.assertEqual(rebuild.diff_configs(a, b),
                         {"layers_published": 2, "layers_rebuilt": 2, "differing_layer_indexes": [1], "differing_labels": {"v": ["1", "2"]}})


class AlertDedupTest(unittest.TestCase):
    def test_select_new(self):
        rep = Report("watch", "nethermind")
        f = rep.add("tag", Status.FAIL, "2.2.0", "release tag moved")
        rep.add("x", Status.PASS, "s", "fine")
        rep.add("y", Status.LEGACY, "s", "old")
        self.assertEqual(alerts.select_new(rep, {}, 1000.0, 24), [f])
        sent = {alerts.finding_key("nethermind", f): 1000.0}
        self.assertEqual(alerts.select_new(rep, sent, 1000.0 + 3600, 24), [])
        self.assertEqual(alerts.select_new(rep, sent, 1000.0 + 25 * 3600, 24), [f])


if __name__ == "__main__":
    unittest.main()
