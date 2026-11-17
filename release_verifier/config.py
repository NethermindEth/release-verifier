"""Project configuration loading, validation and template rendering.

The schema is documented in docs/config.md. Everything project-specific lives in the JSON file;
the core code only knows about generic concepts (tags, signed assets, rebuild steps, OCI images,
distribution channels).
"""

from __future__ import annotations

import json
import os
import re
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PROJECTS_DIR = Path(__file__).resolve().parent.parent / "projects"
CHANNEL_TYPES = ("homebrew", "ppa", "winget")


class ConfigError(Exception):
    pass


class _StrictMap(dict):
    def __missing__(self, key):
        raise ConfigError(f"unknown template variable {{{key}}}")


def render(value: Any, ctx: dict[str, Any]) -> Any:
    """Render ``{var}`` placeholders in strings, recursively through lists and dicts."""
    if isinstance(value, str):
        return string.Formatter().vformat(value, (), _StrictMap(ctx))
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    return value


@dataclass
class Platform:
    name: str
    build_dir: str
    expected_after: str | None = None


@dataclass
class Project:
    path: Path
    raw: dict[str, Any]

    # -- convenience accessors -------------------------------------------------------------
    @property
    def name(self) -> str:
        return self.raw["name"]

    @property
    def repo(self) -> str:
        return self.raw["source"]["repo"]

    @property
    def default_branch(self) -> str:
        return self.raw["source"]["default_branch"]

    @property
    def git_url(self) -> str:
        return self.raw["source"].get("git_url") or f"https://github.com/{self.repo}.git"

    @property
    def tags(self) -> dict[str, Any]:
        return self.raw["tags"]

    @property
    def tag_re(self) -> re.Pattern[str]:
        return re.compile(self.tags["pattern"])

    def version_of(self, tag: str) -> str | None:
        m = self.tag_re.match(tag)
        return m.group("version") if m else None

    def release_ignored(self, tag: str) -> bool:
        """A tag that is not a release of this project (it does not match ``tags.pattern``) but
        matches ``releases.ignore_tag_patterns``: `watch` skips it without a warning."""
        return not self.version_of(tag) and any(re.search(p, tag) for p in (self.raw.get("releases") or {}).get("ignore_tag_patterns", []))

    def signers_dir(self) -> Path:
        """Release-tag signers pinned in this repository (relative to the config file). Tags are
        authenticated against this copy only; `watch` compares it with the upstream directory."""
        return (self.path.parent / self.tags["signers_dir"]).resolve()

    @property
    def signing_key(self) -> dict[str, Any]:
        return self.raw["signing_key"]

    @property
    def fingerprint(self) -> str:
        return normalize_fpr(self.signing_key["fingerprint"])

    def key_file(self) -> Path | None:
        kf = self.signing_key.get("key_file")
        return (self.path.parent / kf).resolve() if kf else None

    @property
    def assets(self) -> dict[str, Any]:
        return self.raw["assets"]

    @property
    def platforms(self) -> list[Platform]:
        return [Platform(p["name"], p.get("build_dir", p["name"]), p.get("expected_after")) for p in self.assets["platforms"]]

    def asset_name(self, version: str, commit: str, platform: str) -> str:
        return render(self.assets["template"], {"version": version, "sha8": commit[:8], "commit": commit, "platform": platform})

    @property
    def attestations(self) -> dict[str, Any]:
        return self.raw.get("attestations") or {}

    @property
    def package_rebuild(self) -> dict[str, Any] | None:
        return self.raw.get("package_rebuild")

    @property
    def images(self) -> dict[str, Any]:
        return self.raw.get("images") or {"flavors": []}

    @property
    def flavors(self) -> list[dict[str, Any]]:
        return self.images.get("flavors", [])

    @property
    def channels(self) -> list[dict[str, Any]]:
        return self.raw.get("channels", [])

    def channel_template(self, channel: dict[str, Any]) -> str | None:
        """Pinned trusted content of a channel (``template``, relative to the config file)."""
        t = channel.get("template")
        return (self.path.parent / t).read_text() if t else None

    @property
    def watch(self) -> dict[str, Any]:
        defaults = {"release_window": 15, "channel_window": 3, "asset_upload_grace_seconds": 0, "channel_grace_hours": 24}
        return {**defaults, **(self.raw.get("watch") or {})}


def normalize_fpr(fpr: str) -> str:
    return fpr.replace(" ", "").upper()


def _require(d: dict[str, Any], keys: list[str], where: str) -> None:
    for k in keys:
        if k not in d:
            raise ConfigError(f"{where}: missing required key '{k}'")


def validate(raw: dict[str, Any]) -> None:
    _require(raw, ["schema_version", "name", "source", "tags", "signing_key", "assets"], "project")
    if raw["schema_version"] != 1:
        raise ConfigError(f"unsupported schema_version {raw['schema_version']}")
    _require(raw["source"], ["repo", "default_branch"], "source")
    _require(raw["tags"], ["pattern", "signers_dir"], "tags")
    try:
        pat = re.compile(raw["tags"]["pattern"])
    except re.error as e:
        raise ConfigError(f"tags.pattern: {e}") from None
    if "version" not in pat.groupindex:
        raise ConfigError("tags.pattern must contain a named group 'version'")
    pins = raw["tags"].get("trusted_commits", {})
    if not isinstance(pins, dict) or not all(isinstance(c, str) and re.fullmatch(r"[0-9a-f]{40}", c) for c in pins.values()):
        raise ConfigError("tags.trusted_commits must map tags to full 40-hex-digit lower-case commit ids")
    if not isinstance(raw.get("releases", {}), dict):
        raise ConfigError("releases must be an object")
    ignore = raw.get("releases", {}).get("ignore_tag_patterns", [])
    if not isinstance(ignore, list) or not all(isinstance(p, str) and p for p in ignore):
        raise ConfigError("releases.ignore_tag_patterns must be a list of non-empty regexes")
    for p in ignore:
        try:
            re.compile(p)
        except re.error as e:
            raise ConfigError(f"releases.ignore_tag_patterns: {p!r}: {e}") from None
    _require(raw["signing_key"], ["fingerprint"], "signing_key")
    if not re.fullmatch(r"[0-9A-F]{40}", normalize_fpr(raw["signing_key"]["fingerprint"])):
        raise ConfigError("signing_key.fingerprint must be a full 40-hex-digit OpenPGP fingerprint")
    _require(raw["assets"], ["template", "platforms"], "assets")
    if "{platform}" not in raw["assets"]["template"]:
        raise ConfigError("assets.template must contain {platform}")
    for p in raw["assets"]["platforms"]:
        _require(p, ["name"], "assets.platforms[]")
    rb = raw.get("package_rebuild")
    if rb is not None:
        _require(rb, ["steps"], "package_rebuild")
        for s in rb["steps"]:
            _require(s, ["run"], "package_rebuild.steps[]")
            if not isinstance(s["run"], list):
                raise ConfigError("package_rebuild.steps[].run must be an argv list")
        if "archive" in rb:
            _require(rb["archive"], ["image", "run", "cwd", "mounts", "output_dir"], "package_rebuild.archive")
            for m in rb["archive"]["mounts"]:
                _require(m, ["source", "target"], "package_rebuild.archive.mounts[]")
    for f in (raw.get("images") or {}).get("flavors", []):
        _require(f, ["name", "dockerfile", "repos", "version_tag", "platforms"], f"images.flavors[{f.get('name')}]")
    bk = (raw.get("images") or {}).get("buildkit_image")
    if bk is not None and not re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", bk):
        raise ConfigError("images.buildkit_image must be an image reference pinned by digest (name:tag@sha256:...)")
    names = set()
    for c in raw.get("channels", []):
        _require(c, ["type", "platforms"], "channels[]")
        if c["type"] not in CHANNEL_TYPES:
            raise ConfigError(f"channels[]: unknown type {c['type']!r} (known: {', '.join(CHANNEL_TYPES)})")
        name = c.get("name", c["type"])
        if name in names:
            raise ConfigError(f"channels[]: duplicate name {name!r}")
        names.add(name)
        required = {"homebrew": ["repo", "path"], "ppa": ["owner", "archive", "source_package"], "winget": ["package_id"]}
        _require(c, required[c["type"]], f"channels[{name}]")
        if c.get("source_dir") and not (isinstance(c.get("changelog"), list) and c["changelog"]):
            raise ConfigError(f"channels[{name}]: source_dir needs the generated changelog lines in 'changelog'")
        pinned = c.get("pinned_fields", {})
        if not isinstance(pinned, dict) or not all(isinstance(v, list) for v in pinned.values()):
            raise ConfigError(f"channels[{name}]: pinned_fields must map manifest keys to lists of values")


def load(project: str) -> Project:
    """Load a project by name (``projects/<name>.json``) or by path."""
    candidates = [Path(project)]
    projects_dir = Path(os.environ.get("RELEASE_VERIFIER_PROJECTS_DIR", PROJECTS_DIR))
    candidates.append(projects_dir / f"{project}.json")
    for c in candidates:
        if c.is_file():
            try:
                raw = json.loads(c.read_text())
            except json.JSONDecodeError as e:
                raise ConfigError(f"{c}: invalid JSON: {e}") from None
            validate(raw)
            p = Project(c.resolve(), raw)
            for ch in p.channels:
                if ch.get("template") and not (p.path.parent / ch["template"]).is_file():
                    raise ConfigError(f"channels[{ch.get('name', ch['type'])}]: template {ch['template']} not found next to {c}")
            return p
    raise ConfigError(f"project {project!r} not found (looked in {', '.join(map(str, candidates))})")
