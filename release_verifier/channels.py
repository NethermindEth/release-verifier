"""Distribution channels that embed release hashes: Homebrew, Launchpad PPA, winget.

Each channel is fetched into a normalized form ``{"version": str, "entries": [{url, sha256, ...}]}``
and evaluated against the hashes of the corresponding release assets. Channels that carry
executable installation logic (the Homebrew formula, the PPA source package) are also compared
against trusted content: a pinned template or the authenticated source tree, where only the
declared substitutions (version, download URLs, hashes, the generated changelog) may differ.
"""

from __future__ import annotations

import difflib
import hashlib
import io
import lzma
import re
import tarfile
import urllib.parse
import zlib
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import github, net
from .checksums import ChecksumsError
from .config import render
from .gpg import Keyring
from .results import Result, Status

LAUNCHPAD_API = "https://api.launchpad.net/1.0"


# -- parsers (pure) -------------------------------------------------------------------------

def parse_homebrew(text: str) -> dict[str, Any]:
    """Formula -> version and ordered ``url``/``sha256`` pairs."""
    version = None
    entries: list[dict[str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if m := re.match(r'^version\s+"([^"]+)"', s):
            if version is not None:
                raise ValueError("formula declares version more than once")
            version = m.group(1)
        elif m := re.match(r'^url\s+"([^"]+)"', s):
            entries.append({"url": m.group(1)})
        elif m := re.match(r'^sha256\s+"([0-9a-fA-F]{64})"', s):
            if not entries or "sha256" in entries[-1]:
                raise ValueError("sha256 without a preceding url in formula")
            entries[-1]["sha256"] = m.group(1).lower()
    return {"version": version, "entries": entries}


def parse_postinst(text: str) -> list[dict[str, str]]:
    """Debian postinst ``url=``/``hash=`` assignments -> ordered pairs."""
    entries: list[dict[str, str]] = []
    for line in text.splitlines():
        s = line.strip()
        if m := re.match(r"^url=['\"]?([^'\"\s]+)['\"]?$", s):
            entries.append({"url": m.group(1)})
        elif m := re.match(r"^hash=['\"]?([0-9a-fA-F]{64})['\"]?$", s):
            if not entries or "sha256" in entries[-1]:
                raise ValueError("hash= without a preceding url= in postinst")
            entries[-1]["sha256"] = m.group(1).lower()
    return entries


def _winget_scalar(value: str, line: str) -> str:
    """A single-line plain or fully quoted scalar; any other YAML construct raises ContentError."""
    v = value.strip()
    if v[:1] in ("{", "[", "|", ">", "&", "*", "!", "%", "@", "`"):
        raise ContentError(f"unsupported YAML construct in winget manifest line {line!r}")
    if v[:1] in ("'", '"'):
        if len(v) < 2 or v[-1] != v[0] or v[0] in v[1:-1]:
            raise ContentError(f"multi-line or irregular quoted scalar in winget manifest line {line!r}")
        return v[1:-1]
    if " #" in v:
        raise ContentError(f"inline comment in winget manifest line {line!r}")
    return v


def parse_winget_installer(text: str) -> dict[str, Any]:
    """Minimal, fail-closed parser for winget installer manifests (flat keys + the ``Installers`` list).

    ``fields`` maps every scalar key, at any depth, to its values in order of appearance, so that
    pinned keys (installer type, nested installer path) can be checked wherever they appear. This is
    not a YAML parser, so anything it could read differently from winget raises ContentError: flow
    collections, block scalars, anchors/aliases/tags, multi-line or continued scalars, tabs,
    several documents, duplicate installer keys, and installer URL/hash set at the root instead of
    in every installer item (each item must carry its own ``InstallerUrl`` and ``InstallerSha256``).
    """
    version = None
    defaults: dict[str, str] = {}
    installers: list[dict[str, str]] = []
    fields: dict[str, list[str]] = {}
    in_installers = False
    item_indent = None
    keymap = {"Architecture": "arch", "InstallerUrl": "url", "InstallerSha256": "sha256"}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise ContentError(f"tab indentation in winget manifest line {raw!r}")
        if raw.startswith(("---", "...")):
            raise ContentError("winget manifest has several YAML documents")
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        body = line.removeprefix("- ") if line.startswith("- ") else line
        fkey, sep, fval = body.partition(":")
        if not sep or (fval and not fval.startswith(" ")) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*", fkey):
            if line.startswith("- ") and ":" not in body:
                _winget_scalar(body, raw)  # a plain list item such as "- silent"
                continue
            raise ContentError(f"unsupported winget manifest line {raw!r}")
        val = _winget_scalar(fval, raw) if fval.strip() else ""
        if val:
            fields.setdefault(fkey, []).append(val)
        if indent == 0 and not line.startswith("-"):
            in_installers = fkey == "Installers"
            if fkey == "PackageVersion":
                version = val
            elif fkey == "Architecture":
                defaults["arch"] = val
            elif fkey in keymap:
                raise ContentError(f"{fkey} is set at the manifest root; every installer must set its own")
            continue
        if not in_installers:
            continue
        if line.startswith("- "):
            if item_indent is None:
                item_indent = indent
            if indent == item_indent:
                installers.append({})
        if not installers:
            continue
        if fkey in keymap and (item_indent is None or indent <= item_indent + 2):
            if keymap[fkey] in installers[-1]:
                raise ContentError(f"installer sets {fkey} twice")
            installers[-1][keymap[fkey]] = val
    entries = []
    for i in installers:
        if not i.get("url") or not i.get("sha256"):
            raise ContentError("an installer item lacks its own InstallerUrl or InstallerSha256")
        e = {**defaults, **i, "sha256": i["sha256"].lower()}
        entries.append(e)
    return {"version": version, "entries": entries, "fields": fields}


def winget_manifest_path(package_id: str, version: str) -> str:
    parts = package_id.split(".")
    return f"manifests/{parts[0][0].lower()}/{'/'.join(parts)}/{version}/{package_id}.installer.yaml"


def parse_dsc_sha256(text: str) -> dict[str, str]:
    """``Checksums-Sha256`` field of a Debian source control file -> ``{file: hex}``."""
    out: dict[str, str] = {}
    in_field = False
    for line in text.splitlines():
        if line.startswith("Checksums-Sha256:"):
            in_field = True
            continue
        if in_field:
            if not line.startswith(" "):
                break
            parts = line.split()
            if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{64}", parts[0]):
                raise ChecksumsError(f"malformed Checksums-Sha256 line: {line!r}")
            out[parts[2]] = parts[0]
    return out


# -- trusted content (pure) -----------------------------------------------------------------

CHANGELOG = "debian/changelog"
TEXT_LIMIT = 256 * 1024
DIFF_LINES = 80
RFC2822_DATE = r"(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} [+-]\d{4}"
_PLACEHOLDER = re.compile(r"\{\{([a-z0-9]+)(?::([^{}]+))?\}\}")
# Caps for published source packages (the Nethermind one is a few KB): a decompression bomb is a
# finding for that version, never an out-of-memory kill of the whole run.
MAX_DOWNLOAD = 32 * 1024 * 1024
MAX_MEMBERS = 10_000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024


class ContentError(ValueError):
    """Published channel content that cannot be accepted (malformed, unexpected or over a cap)."""


def _member_name(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    return name.rstrip("/")


def tar_tree(data: bytes, root: str | None = None) -> dict[str, dict[str, Any]]:
    """Non-directory members of a tarball, keyed by their path below ``root`` (default: the single
    top-level directory, as in a native Debian source package).

    Files are ``{"type": "file", "sha256", "text"?}`` (text for small UTF-8 files), symlinks
    ``{"type": "symlink", "target"}``, anything else ``{"type": "other"}``. The archive is read as a
    stream and member contents are hashed in chunks, within MAX_MEMBERS / MAX_MEMBER_BYTES /
    MAX_TOTAL_BYTES (ContentError beyond them).
    """
    out: dict[str, dict[str, Any]] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r|*") as tf:
            for count, m in enumerate(tf, 1):
                if count > MAX_MEMBERS:
                    raise ContentError(f"source tarball has more than {MAX_MEMBERS} members")
                name = _member_name(m.name)
                if not name:
                    continue
                if root is None:
                    root = name.split("/", 1)[0] + "/"
                if m.isdir():
                    continue
                if not name.startswith(root):
                    raise ContentError(f"tarball member {m.name!r} is outside {root} (expected one top-level directory)")
                if m.isfile():
                    if m.size > MAX_MEMBER_BYTES or total + m.size > MAX_TOTAL_BYTES:
                        raise ContentError(f"tarball member {m.name!r} ({m.size} bytes) exceeds the size caps")
                    total += m.size
                    h, head = hashlib.sha256(), b""
                    f = tf.extractfile(m)
                    while chunk := f.read(1 << 20):
                        h.update(chunk)
                        if len(head) <= TEXT_LIMIT:
                            head += chunk
                    e: dict[str, Any] = {"type": "file", "sha256": h.hexdigest()}
                    if m.size <= TEXT_LIMIT:
                        try:
                            e["text"] = head.decode()
                        except UnicodeDecodeError:
                            pass
                elif m.issym():
                    e = {"type": "symlink", "target": m.linkname}
                else:
                    e = {"type": "other"}
                out[name[len(root):]] = e
    except (tarfile.TarError, EOFError, OSError, lzma.LZMAError, zlib.error) as e:
        raise ContentError(f"unreadable tarball: {type(e).__name__}: {e}") from None
    return out


def without_texts(tree: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The comparable part of a tree (what verification records keep)."""
    return {p: {k: v for k, v in e.items() if k != "text"} for p, e in tree.items()}


def rewrite_assignments(text: str, key: str, values: list[str]) -> str:
    """For N = 1, 2, ...: ``awk -v n=N '/key/ { if (++count == n) sub(/key.*/, "key=VALUE") } 1'``,
    the rewrite publish-packages.yml applies to ``debian/postinst``. The N-th line containing ``key``
    has everything from its first ``key`` on replaced by ``key=values[N-1]``."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for n, value in enumerate(values, 1):
        count = 0
        for i, line in enumerate(lines):
            if key in line:
                count += 1
                if count == n:
                    lines[i] = line[: line.index(key)] + f"{key}={value}"
                    break
    return "".join(line + "\n" for line in lines)


def _file_entry(text: str) -> dict[str, Any]:
    return {"type": "file", "sha256": hashlib.sha256(text.encode()).hexdigest(), "text": text}


def ppa_reference(tree: dict[str, dict[str, Any]], file: str, entries: list[dict[str, str]]) -> dict[str, dict[str, Any]]:
    """The source package publish-packages.yml builds from the trusted ``tree``: ``file`` gets the
    n-th ``url=``/``hash=`` of ``entries`` (in channel platform order); ``debian/changelog`` is
    generated by the workflow and checked by shape instead, so it is not part of the reference."""
    ref = {p: e for p, e in tree.items() if p != CHANGELOG}
    text = (ref.get(file) or {}).get("text")
    if text is None:
        raise ValueError(f"{file} is not a text file in the trusted source tree")
    text = rewrite_assignments(text, "url", [e["url"] for e in entries])
    ref[file] = _file_entry(rewrite_assignments(text, "hash", [e["sha256"] for e in entries]))
    return ref


def changelog_matches(text: str, lines: list[str], version: str) -> bool:
    """``text`` is exactly ``lines`` (templates with ``{version}`` and ``{date}``, an RFC 2822 date)
    plus the newline ``echo`` appends."""
    rendered = (RFC2822_DATE.join(re.escape(render(part, {"version": version})) for part in line.split("{date}")) for line in lines)
    return re.fullmatch("\n".join(rendered) + "\n", text) is not None


def render_template(template: str, version: str, assets: dict[str, dict[str, str]]) -> str:
    """Fill ``{{version}}``, ``{{url:<platform>}}`` and ``{{sha256:<platform>}}`` in a pinned template."""
    def sub(m: re.Match[str]) -> str:
        kind, platform = m.group(1), m.group(2)
        if kind == "version" and platform is None:
            return version
        if kind in ("url", "sha256") and platform:
            value = (assets.get(platform) or {}).get(kind)
            if not value:
                raise KeyError(platform)
            return value
        raise ValueError(f"unknown template placeholder {m.group(0)}")
    return _PLACEHOLDER.sub(sub, template)


def _text_diff(trusted: str, published: str, name: str) -> str:
    lines = difflib.unified_diff(trusted.splitlines(), published.splitlines(), f"trusted/{name}", f"published/{name}", lineterm="")
    return "\n".join(list(lines)[:DIFF_LINES])


# -- evaluation (pure) ----------------------------------------------------------------------

def evaluate(
    channel: str,
    version: str,
    entries: list[dict[str, str]],
    expected: dict[str, dict[str, str]],
    platforms: list[str],
) -> list[Result]:
    """Compare channel entries against expected assets.

    ``expected`` maps platform -> {"asset", "url", "sha256", "source"} for assets that exist in the
    release. Every entry must reference a known asset by its canonical download URL with the
    expected hash; every configured platform that has an asset must be covered.
    """
    results: list[Result] = []
    by_asset = {e["asset"]: (p, e) for p, e in expected.items()}
    covered: set[str] = set()
    subject = f"{channel}@{version}"
    for entry in entries:
        url = entry.get("url", "")
        asset = urllib.parse.unquote(urllib.parse.urlsplit(url).path.rsplit("/", 1)[-1])
        if asset not in by_asset:
            results.append(Result("channel-hash", Status.FAIL, subject, f"entry points to an unknown asset: {url}", {"entry": entry}))
            continue
        platform, exp = by_asset[asset]
        covered.add(platform)
        if url != exp["url"]:
            results.append(Result("channel-hash", Status.FAIL, subject, f"{platform}: URL {url} is not the release download URL {exp['url']}", {"entry": entry}))
        elif entry.get("sha256") != exp["sha256"]:
            results.append(Result(
                "channel-hash", Status.FAIL, subject,
                f"{platform}: hash {entry.get('sha256')} != expected {exp['sha256']} ({exp['source']})",
                {"entry": entry, "expected": exp},
            ))
        else:
            results.append(Result("channel-hash", Status.PASS, subject, f"{platform}: hash matches ({exp['source']})", {"sha256": exp["sha256"]}))
    for p in platforms:
        if p in expected and p not in covered:
            results.append(Result("channel-hash", Status.WARN, subject, f"{p}: release has {expected[p]['asset']} but the channel does not offer it"))
    if not entries:
        results.append(Result("channel-hash", Status.FAIL, subject, "channel lists no downloadable entries"))
    return results


def evaluate_source_tree(
    subject: str, published: dict[str, dict[str, Any]], reference: dict[str, dict[str, Any]], changelog: list[str], version: str, trusted: str,
) -> Result:
    """Every file of a published source package must equal the trusted reference; the generated
    changelog must have exactly the configured shape. Anything else is a compromise-class change."""
    problems: list[str] = []
    diffs: dict[str, str] = {}
    log = published.get(CHANGELOG) or {}
    if "text" not in log or not changelog_matches(log["text"], changelog, version):
        problems.append(f"{CHANGELOG} is not the generated changelog")
        diffs[CHANGELOG] = log.get("text", "<missing or binary>")[:2000]
    for path in sorted((published.keys() | reference.keys()) - {CHANGELOG}):
        want, got = reference.get(path), published.get(path)
        if got is None:
            problems.append(f"{path} removed")
        elif want is None:
            problems.append(f"{path} added")
            diffs[path] = got.get("text", f"<{got['type']}>")[:2000]
        elif any(want.get(k) != got.get(k) for k in ("type", "sha256", "target")):
            problems.append(f"{path} changed")
            if "text" in want and "text" in got:
                diffs[path] = _text_diff(want["text"], got["text"], path)
    if problems:
        return Result("channel-content", Status.FAIL, subject,
                      f"published source differs from {trusted} beyond the declared substitutions: {'; '.join(problems[:10])}",
                      {"problems": problems, "diffs": diffs})
    return Result("channel-content", Status.PASS, subject, f"published source equals {trusted} except the declared substitutions ({len(reference) + 1} files)")


def evaluate_template(subject: str, published: str, expected: str, template: str) -> Result:
    """Byte equality with the rendered pinned template (only a trailing newline is normalized)."""
    if published.rstrip("\n") == expected.rstrip("\n"):
        return Result("channel-content", Status.PASS, subject, f"equals the pinned template {template} with the release's version, URLs and hashes")
    return Result("channel-content", Status.FAIL, subject,
                  f"differs from the pinned template {template}; a legitimate change needs a reviewed template update in this repository",
                  {"diff": _text_diff(expected, published, template)})


def evaluate_template_shape(subject: str, published: str, template_text: str, version: str, template: str) -> Result:
    """The pinned template with only its URL/hash slots left open (GitHub download URLs, 64 hex
    digits): checks the formula body when no release hashes are available to render it exactly."""
    text = template_text.rstrip("\n")
    parts, pos = [], 0
    for m in _PLACEHOLDER.finditer(text):
        parts.append(re.escape(text[pos:m.start()]))
        kind = m.group(1)
        parts.append(re.escape(version) if kind == "version" else r"https://github\.com/[^\"\s]+" if kind == "url" else "[0-9a-f]{64}")
        pos = m.end()
    parts.append(re.escape(text[pos:]))
    if re.fullmatch("".join(parts), published.rstrip("\n")):
        return Result("channel-content", Status.PASS, subject, f"matches the pinned template {template} (URLs and hashes not rendered: no release hashes)")
    return Result("channel-content", Status.FAIL, subject,
                  f"differs from the pinned template {template}; a legitimate change needs a reviewed template update in this repository",
                  {"diff": _text_diff(template_text, published, template)})



def evaluate_pinned_fields(subject: str, fields: dict[str, list[str]], pinned: dict[str, list[str]]) -> Result:
    """Declarative manifest keys that decide what gets run (installer type, nested executable)."""
    bad = {k: sorted(set(fields.get(k, []))) for k, want in pinned.items() if sorted(set(fields.get(k, []))) != sorted(set(want))}
    if bad:
        return Result("channel-content", Status.FAIL, subject, f"pinned manifest fields changed: {bad} (pinned {pinned})", {"found": bad, "pinned": pinned})
    return Result("channel-content", Status.PASS, subject, f"pinned manifest fields unchanged ({', '.join(sorted(pinned))})")


# -- fetchers -------------------------------------------------------------------------------

def fetch_homebrew(ch: dict[str, Any]) -> dict[str, Any]:
    """The tap as brew sees it: its default branch, every path of that branch's tree, and the
    formula read from that exact commit. An unparsable formula is recorded as ``malformed``."""
    tap = github.repo_snapshot(ch["repo"])
    out: dict[str, Any] = {"tap": tap, "version": None, "entries": [], "text": None}
    if tap["tree"].get(ch["path"], [None])[0] != "blob":
        out["malformed"] = f"{ch['path']} is not a file on {tap['default_branch']}"
        return out
    try:
        text = net.get_bytes(github.raw_url(ch["repo"], tap["commit"], ch["path"]), limit=1024 * 1024).decode()
        out["text"] = text
        out.update(parse_homebrew(text))
    except (ValueError, UnicodeDecodeError) as e:  # TooLarge, orphan sha256, undecodable
        out["malformed"] = str(e)
    return out


def winget_versions(ch: dict[str, Any]) -> list[str]:
    """Every version directory under the package's manifest directory."""
    path = winget_manifest_path(ch["package_id"], "_").rsplit("/", 2)[0]
    listing = github.list_dir(ch.get("repo", "microsoft/winget-pkgs"), ch.get("branch", "master"), path) or []
    return sorted(e["name"] for e in listing if e.get("type") == "dir")


def fetch_winget(ch: dict[str, Any], version: str) -> dict[str, Any] | None:
    """The installer manifest of ``version``; None when not published. A manifest that cannot be
    parsed safely is ``{"malformed": reason}`` (a finding for that version)."""
    url = github.raw_url(ch.get("repo", "microsoft/winget-pkgs"), ch.get("branch", "master"), winget_manifest_path(ch["package_id"], version))
    try:
        data = net.get_bytes(url, limit=1024 * 1024)
    except net.HttpError as e:
        if e.status == 404:
            return None
        raise
    except net.TooLarge as e:
        return {"malformed": str(e)}
    try:
        return parse_winget_installer(data.decode())
    except (ContentError, UnicodeDecodeError) as e:
        return {"malformed": str(e)}


def ppa_published_versions(ch: dict[str, Any]) -> dict[str, dict[str, dict[str, Any]]]:
    """Every published source in the archive: package name -> version -> {"series", "links"}."""
    url = f"{LAUNCHPAD_API}/~{ch['owner']}/+archive/ubuntu/{ch['archive']}?ws.op=getPublishedSources&status=Published"
    out: dict[str, dict[str, dict[str, Any]]] = {}
    while url:
        data = net.get_json(url)
        for e in data.get("entries", []):
            v = out.setdefault(e["source_package_name"], {}).setdefault(e["source_package_version"], {"series": [], "links": []})
            v["series"].append(e["distro_series_link"].rsplit("/", 1)[-1])
            v["links"].append(e["self_link"])
        url = data.get("next_collection_link")
    for versions in out.values():
        for v in versions.values():
            v["series"].sort()
    return out


def fetch_ppa_version(ch: dict[str, Any], info: dict[str, Any], dsc_key: bytes | None) -> dict[str, Any]:
    """Download the published source of one version and extract the release URLs/hashes.

    Also checks the .dsc upload signature (when ``dsc_signing_fingerprint`` is set) and that the
    source matches the .dsc, so a Launchpad-account-only compromise is visible. The source must be
    a native package (``Format: 3.0 (native)``) made of exactly the .dsc and one tarball, listed in
    the .dsc: anything else (a ``.diff.gz`` dpkg-source would apply, extra files) is recorded in
    ``problems``. With ``source_dir`` set, the tarball's file tree is kept (``trees``) for the
    content check. Content that cannot be accepted raises ContentError.
    """
    files: list[str] = []
    for link in info["links"]:
        try:
            listing = net.get_json(f"{link}?ws.op=sourceFileUrls")
        except ValueError as e:  # an unreadable Launchpad API response is an infra problem, not content
            raise RuntimeError(f"Launchpad sourceFileUrls: {e}") from None
        for f in listing:
            if f not in files:
                files.append(f)
    names = {f.rsplit("/", 1)[-1]: f for f in files}
    dscs = [n for n in names if n.endswith(".dsc")]
    if len(dscs) != 1:
        raise ContentError(f"published source has {len(dscs)} .dsc files, expected one")
    result: dict[str, Any] = {"series": info["series"], "files": sorted(names), "problems": []}
    dsc_bytes = net.get_bytes(names[dscs[0]], limit=1024 * 1024)
    fpr = ch.get("dsc_signing_fingerprint")
    if fpr and dsc_key:
        with Keyring() as kr:
            kr.import_key_data(dsc_key)
            p = kr.home / "src.dsc"
            p.write_bytes(dsc_bytes)
            check, signed = kr.verify_clearsigned(p, fpr)
        result["dsc_signature"] = check.outcome
        # Only trust fields from the signed portion when the signature is valid.
        dsc_text = signed.decode(errors="replace") if check.valid else dsc_bytes.decode(errors="replace")
    else:
        dsc_text = dsc_bytes.decode(errors="replace")
    problems = result["problems"]
    fmt = parse_dsc_field(dsc_text, "Format")
    if fmt != "3.0 (native)":
        problems.append(f".dsc Format is {fmt!r}, expected '3.0 (native)' (a non-native package carries a diff dpkg-source applies)")
    sums = parse_dsc_sha256(dsc_text)
    others = sorted(set(names) - {dscs[0]})
    if len(others) != 1 or not re.search(r"\.tar\.(xz|gz|bz2)$", others[0]):
        problems.append(f"published source is {', '.join(sorted(names))}; expected the .dsc and exactly one tarball")
    if sorted(sums) != others:
        problems.append(f".dsc lists {', '.join(sorted(sums)) or 'no files'}, published {', '.join(others) or 'none'}")
    tarballs = [n for n in others if ".tar." in n]
    if len(tarballs) != 1:
        raise ContentError(f"published source has {len(tarballs)} tarballs, expected one")
    name = tarballs[0]
    data = net.get_bytes(names[name], limit=MAX_DOWNLOAD)
    result["tarball_matches_dsc"] = sums.get(name) == hashlib.sha256(data).hexdigest()
    tree = tar_tree(data)
    if ch.get("source_dir"):
        result["trees"] = {name: tree}
    member = ch.get("file", "debian/postinst")
    text = (tree.get(member) or {}).get("text")
    if text is None:
        raise ContentError(f"{member} not found (or not a small text file) in the published source")
    result["entries"] = parse_postinst(text)
    return result


def parse_dsc_field(text: str, field: str) -> str | None:
    """Single-line field of a Debian control paragraph."""
    for line in text.splitlines():
        if line.startswith(f"{field}:"):
            return line.partition(":")[2].strip()
    return None


def _ppa_dsc_sha256(info: dict[str, Any]) -> str:
    """sha256 of a published version's .dsc (for uploads pinned in ``legacy_uploads``)."""
    dscs = {f for link in info["links"] for f in net.get_json(f"{link}?ws.op=sourceFileUrls") if f.endswith(".dsc")}
    if len(dscs) != 1:
        raise ContentError(f"published source has {len(dscs)} .dsc files, expected one")
    return hashlib.sha256(net.get_bytes(dscs.pop(), limit=1024 * 1024)).hexdigest()


def fetch_ppa(ch: dict[str, Any], fetch: set[str] | None, dsc_key: bytes | None) -> dict[str, Any]:
    """Every source published in the PPA. ``sources``: versions of ``source_package``; those in
    ``fetch`` (None: all) are downloaded and parsed, those pinned in ``legacy_uploads`` get their
    .dsc hashed, the others are only listed (they must not exist without a verified release).
    ``other_packages``: any other source package name -> versions (never expected)."""
    published = ppa_published_versions(ch)
    own = published.pop(ch["source_package"], {})
    legacy = ch.get("legacy_uploads") or {}
    jobs: dict[str, Any] = {}
    with ThreadPoolExecutor(max_workers=4) as pool:
        for v, info in own.items():
            if fetch is None or v in fetch:
                jobs[v] = pool.submit(fetch_ppa_version, ch, info, dsc_key)
            elif v in legacy:
                jobs[v] = pool.submit(lambda info=info: {"legacy_dsc_sha256": _ppa_dsc_sha256(info)})
    sources: dict[str, Any] = {}
    for v, info in own.items():
        # Recorded per version; a single bad upload must not hide the others. Published content that
        # cannot be accepted is a finding (malformed); anything else is a tool/transport error.
        if v not in jobs:
            sources[v] = {"series": info["series"], "not_fetched": True}
            continue
        try:
            sources[v] = {"series": info["series"], **jobs[v].result()}
        except ValueError as e:  # ContentError, ChecksumsError, TooLarge, parse errors
            sources[v] = {"malformed": str(e), "series": info["series"]}
        except Exception as e:  # noqa: BLE001
            sources[v] = {"error": str(e), "series": info["series"]}
    return {"sources": sources, "other_packages": {name: sorted(vs) for name, vs in sorted(published.items())}}
