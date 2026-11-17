"""Independent rebuilds (packages and OCI images) and their comparison with published artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import render

LIST_LIMIT = 50
LOG_TAIL = 2000


class RebuildError(Exception):
    pass


def run_logged(argv: list[str], cwd: Path, log_file: Path, env: dict[str, str] | None = None, name: str = "") -> None:
    """Run a command, appending its output to ``log_file``. Raises RebuildError on failure."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "ab") as log:
        log.write(f"\n=== {name or argv[0]}: {' '.join(argv)} (cwd={cwd})\n".encode())
        log.flush()
        p = subprocess.run(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, env={**os.environ, **(env or {})})
    if p.returncode != 0:
        raise RebuildError(f"step '{name or argv[0]}' exited {p.returncode}; log tail:\n{log_tail(log_file)}")


def log_tail(log_file: Path, limit: int = LOG_TAIL) -> str:
    """The last ``limit`` bytes of a (possibly multi-GB) build log, read from the end."""
    with open(log_file, "rb") as f:
        size = f.seek(0, os.SEEK_END)
        f.seek(max(0, size - limit))
        return f.read().decode(errors="replace")


# -- package rebuild ------------------------------------------------------------------------

def rebuild_packages(recipe: dict[str, Any], ctx: dict[str, Any], src_dir: Path, log_file: Path, no_cache: bool = False) -> None:
    """Run the configured build steps in the release checkout; output lands in ``ctx['out_dir']``.

    With ``no_cache``, steps declaring ``no_cache_flag`` get it appended, so nothing from an earlier
    (possibly poisoned) local build cache is reused.
    """
    try:
        for step in recipe["steps"]:
            argv = render(step["run"], ctx) + ([step["no_cache_flag"]] if no_cache and step.get("no_cache_flag") else [])
            run_logged(argv, src_dir, log_file, render(step.get("env", {}), ctx), step.get("name", ""))
    finally:
        for argv in recipe.get("cleanup", []):
            subprocess.run(render(argv, ctx), cwd=src_dir, capture_output=True)


def ensure_local_image(dockerfile: Path, name: str, log_file: Path) -> str:
    """Build (once) an image from a Dockerfile shipped with this repository, with no build context;
    the tag carries the Dockerfile's hash so an edited file never reuses a stale image."""
    data = dockerfile.read_bytes()
    tag = f"{name}:{hashlib.sha256(data).hexdigest()[:16]}"
    if subprocess.run(["docker", "image", "inspect", tag], capture_output=True).returncode == 0:
        return tag
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "ab") as log:
        log.write(f"\n=== build {tag} from {dockerfile}\n".encode())
        log.flush()
        p = subprocess.run(["docker", "build", "-t", tag, "-"], input=data, stdout=log, stderr=subprocess.STDOUT)
    if p.returncode != 0:
        raise RebuildError(f"building {tag} from {dockerfile} exited {p.returncode}; log tail:\n{log_tail(log_file)}")
    return tag


def archive_packages(recipe: dict[str, Any], ctx: dict[str, Any], log_file: Path, config_dir: Path) -> Path:
    """Run the project's archive step (byte-reproducible zips) in a container built from
    ``archive.image`` (a Dockerfile in this repository): no network, the invoking user, only the
    declared environment, every mount read-only except the ``writable`` ones (recreated empty).
    Returns the archive output dir."""
    arc = recipe["archive"]
    image = ensure_local_image(config_dir / arc["image"], "release-verifier-archive", log_file)
    argv = ["docker", "run", "--rm", "--network", "none", "--user", f"{ctx['uid']}:{ctx['gid']}", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp", "--workdir", render(arc["cwd"], ctx)]
    for m in arc["mounts"]:
        source = Path(render(m["source"], ctx))
        if m.get("writable"):
            if source.exists():
                shutil.rmtree(source)
            source.mkdir(parents=True)
        elif not is_plain_dir(source):
            raise RebuildError(f"archive mount source {source} is not a directory")
        argv += ["--mount", f"type=bind,source={source},target={m['target']}" + ("" if m.get("writable") else ",readonly")]
    for k, v in render(arc.get("env", {}), ctx).items():
        argv += ["--env", f"{k}={v}"]
    argv += [image, *render(arc["run"], ctx)]
    run_logged(argv, Path(ctx["work_dir"]), log_file, name="archive")
    return Path(render(arc["output_dir"], ctx))


def is_plain_dir(path: Path) -> bool:
    """A real directory (checked with lstat): a symlink, even to a directory, is not."""
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except FileNotFoundError:
        return False


# -- tree comparison ------------------------------------------------------------------------

@dataclass
class Entry:
    kind: str  # file | dir | symlink
    sha256: str | None = None  # file content hash, or symlink target for symlinks
    mode: int | None = None  # permission bits (0o777), when known


def _norm(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def zip_entries(path: Path) -> dict[str, Entry]:
    out: dict[str, Entry] = {}
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            name = _norm(info.filename)
            if not name:
                continue
            unix = info.create_system == 3
            mode = (info.external_attr >> 16) if unix else 0
            if unix and stat.S_ISLNK(mode):
                out[name] = Entry("symlink", z.read(info).decode("utf-8", "surrogateescape"), None)
            elif info.is_dir() or (unix and stat.S_ISDIR(mode)):
                out[name] = Entry("dir", None, None)
            else:
                h = hashlib.sha256()
                with z.open(info) as f:
                    while chunk := f.read(1 << 20):
                        h.update(chunk)
                out[name] = Entry("file", h.hexdigest(), (mode & 0o777) if unix and mode else None)
    return out


def tree_entries(root: Path) -> dict[str, Entry]:
    out: dict[str, Entry] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        for d in list(dirnames):
            p = base / d
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                out[rel] = Entry("symlink", os.readlink(p), None)
                dirnames.remove(d)
            else:
                out[rel] = Entry("dir", None, None)
        for f in filenames:
            p = base / f
            rel = p.relative_to(root).as_posix()
            if p.is_symlink():
                out[rel] = Entry("symlink", os.readlink(p), None)
                continue
            h = hashlib.sha256()
            with open(p, "rb") as fh:
                while chunk := fh.read(1 << 20):
                    h.update(chunk)
            out[rel] = Entry("file", h.hexdigest(), p.lstat().st_mode & 0o777)
    return out


@dataclass
class TreeDiff:
    compared: int = 0
    missing_in_rebuild: list[str] = field(default_factory=list)
    extra_in_rebuild: list[str] = field(default_factory=list)
    content_mismatch: list[str] = field(default_factory=list)
    kind_mismatch: list[str] = field(default_factory=list)
    mode_mismatch: list[str] = field(default_factory=list)

    @property
    def contents_match(self) -> bool:
        return not (self.missing_in_rebuild or self.extra_in_rebuild or self.content_mismatch or self.kind_mismatch)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"compared": self.compared}
        for k in ("missing_in_rebuild", "extra_in_rebuild", "content_mismatch", "kind_mismatch", "mode_mismatch"):
            v = getattr(self, k)
            if v:
                out[k] = v[:LIST_LIMIT]
                if len(v) > LIST_LIMIT:
                    out[k + "_total"] = len(v)
        return out


def compare_entries(published: dict[str, Entry], rebuilt: dict[str, Entry]) -> TreeDiff:
    """Compare a published archive's entries against a rebuilt tree.

    Directories only count when the archive records them explicitly (many zips omit them).
    Permission bits are reported separately: legacy archives were not built with fixed modes.
    """
    d = TreeDiff()
    has_dirs = any(e.kind == "dir" for e in published.values())
    reb = {k: v for k, v in rebuilt.items() if has_dirs or v.kind != "dir"}
    for name in sorted(published.keys() - reb.keys()):
        d.missing_in_rebuild.append(name)
    for name in sorted(reb.keys() - published.keys()):
        d.extra_in_rebuild.append(name)
    for name in sorted(published.keys() & reb.keys()):
        a, b = published[name], reb[name]
        d.compared += 1
        if a.kind != b.kind:
            d.kind_mismatch.append(f"{name} ({a.kind} vs {b.kind})")
        elif a.sha256 != b.sha256:
            d.content_mismatch.append(name)
        elif a.kind == "file" and a.mode is not None and b.mode is not None and (a.mode & 0o111) != (b.mode & 0o111):
            d.mode_mismatch.append(f"{name} ({oct(a.mode)} vs {oct(b.mode)})")
    return d


# -- image rebuild --------------------------------------------------------------------------

def ensure_builder(name: str, log_file: Path, buildkit_image: str | None = None) -> None:
    """Make sure a docker-container buildx builder exists (needed for OCI export + rewrite-timestamp).

    With ``buildkit_image`` (``images.buildkit_image``: the BuildKit the release workflow pins), the
    builder must run exactly that image: layer compression, rewrite-timestamp handling and the
    Dockerfile frontend change between BuildKit versions, so another one cannot reproduce the
    published images. A missing builder is created with it; an existing builder running anything
    else is an error (it is not recreated behind the operator's back)."""
    p = subprocess.run(["docker", "buildx", "inspect", name], capture_output=True)
    if p.returncode != 0:
        argv = ["docker", "buildx", "create", "--name", name, "--driver", "docker-container"]
        if buildkit_image:
            argv += ["--driver-opt", f"image={buildkit_image}"]
        run_logged(argv, Path.cwd(), log_file, name="buildx create")
        return
    out = p.stdout.decode(errors="replace")
    if "docker-container" not in out:
        raise RebuildError(f"buildx builder {name!r} must use the docker-container driver")
    if buildkit_image:
        m = re.search(r'^Driver Options:.*\bimage="([^"]*)"', out, re.MULTILINE)
        running = m.group(1) if m else None
        if running != buildkit_image:
            raise RebuildError(f"buildx builder {name!r} runs BuildKit image {running or '(the buildx default)'}, not the pinned {buildkit_image}; "
                               f"remove it (docker buildx rm {name}) so it is recreated, or pass another --builder")


def build_image(
    flavor: dict[str, Any], platform: str, ctx: dict[str, Any], src_dir: Path, builder: str, out_tar: Path, log_file: Path, no_cache: bool
) -> None:
    rewrite = ",rewrite-timestamp=true" if flavor.get("rewrite_timestamp", True) else ""
    argv = [
        "docker", "buildx", "build", ".",
        "--builder", builder,
        "--platform", platform,
        "-f", flavor["dockerfile"],
        "--provenance=false", "--sbom=false",
        "--output", f"type=oci,dest={out_tar}{rewrite}",
    ]
    for k, v in render(flavor.get("build_args", {}), ctx).items():
        argv += ["--build-arg", f"{k}={v}"]
    if no_cache:
        argv.append("--no-cache")
    out_tar.parent.mkdir(parents=True, exist_ok=True)
    run_logged(argv, src_dir, log_file, {"SOURCE_DATE_EPOCH": str(ctx["source_date_epoch"])}, f"image {flavor['name']} {platform}")


def oci_layout_image(tar_path: Path, platform: str | None = None) -> dict[str, Any]:
    """Manifest/config digests and the config document of the image in an OCI layout tarball."""
    with tarfile.open(tar_path) as tf:
        def blob(digest: str) -> bytes:
            algo, _, hexd = digest.partition(":")
            return tf.extractfile(f"blobs/{algo}/{hexd}").read()

        doc = json.loads(tf.extractfile("index.json").read())
        desc = None
        while True:
            manifests = doc.get("manifests", [])
            images = [m for m in manifests if (m.get("annotations") or {}).get("vnd.docker.reference.type") != "attestation-manifest"]
            if platform:
                plat = [m for m in images if m.get("platform") and f"{m['platform'].get('os')}/{m['platform'].get('architecture')}" == platform]
                images = plat or images
            if len(images) != 1:
                raise RebuildError(f"expected exactly one image in {tar_path.name}, found {len(images)}")
            desc = images[0]
            child = json.loads(blob(desc["digest"]))
            if "manifests" in child:
                doc = child
                continue
            manifest = child
            break
        config_bytes = blob(manifest["config"]["digest"])
        return {
            "manifest": desc["digest"],
            "config": manifest["config"]["digest"],
            "config_doc": json.loads(config_bytes),
            "layers": [l["digest"] for l in manifest.get("layers", [])],
        }


def diff_configs(published: dict[str, Any], rebuilt: dict[str, Any]) -> dict[str, Any]:
    """Explain an image config mismatch: which diff_ids (layers) and labels differ."""
    a = (published.get("rootfs") or {}).get("diff_ids", [])
    b = (rebuilt.get("rootfs") or {}).get("diff_ids", [])
    layers = [i for i in range(max(len(a), len(b))) if (a[i] if i < len(a) else None) != (b[i] if i < len(b) else None)]
    la = (published.get("config") or {}).get("Labels") or {}
    lb = (rebuilt.get("config") or {}).get("Labels") or {}
    labels = sorted(k for k in la.keys() | lb.keys() if la.get(k) != lb.get(k))
    out: dict[str, Any] = {"layers_published": len(a), "layers_rebuilt": len(b), "differing_layer_indexes": layers}
    if labels:
        out["differing_labels"] = {k: [la.get(k), lb.get(k)] for k in labels}
    if published.get("created") != rebuilt.get("created"):
        out["created"] = [published.get("created"), rebuilt.get("created")]
    return out
