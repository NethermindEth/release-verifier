# Project configuration schema

One JSON file per project under `projects/<name>.json` (or any path passed to `--project`).
`release-verifier check-config --project <name>` validates it. `projects/nethermind.json` is the
reference example.

## Templates

String values marked *template* may use `{variable}` placeholders. An unknown variable is a config
error, never an empty string. Variables available:

| Variable | Meaning |
|---|---|
| `version` | version captured by `tags.pattern` |
| `tag` | the git tag |
| `commit` / `sha8` | full / 8-char commit the tag peels to |
| `source_date_epoch` | committer timestamp of `commit` (seconds) |
| `build_timestamp` | the same instant as `%Y-%m-%dT%H:%M:%SZ` (UTC) |
| `work_dir` | per-release scratch dir (`<work>/<project>/<tag>`) |
| `src_dir` | checkout of `commit` (`{work_dir}/src`) |
| `out_dir` | empty dir for the package build output (`{work_dir}/out`) |
| `uid` / `gid` | ids of the user running the verifier |
| `build_image` | a unique local image tag for the package build |
| `project` / `repo` | project name / `owner/name` |
| `platform` | (asset template only) platform name |

## Feature cutoffs (`*_expected_after`)

Controls are adopted over time. A key such as `signed_expected_after: "2.2.2"` means "required for
every version **greater than** 2.2.2" (SemVer precedence, so `2.3.0-rc.1` is already covered).
For releases at or below the cutoff a missing control is reported as `legacy` (exit code 0); above
it, the same gap is `fail`. A control that is present is always verified, whatever the version.
`null` or an absent key means "always required".

## Keys

### Top level

| Key | Type | Required | Notes |
|---|---|---|---|
| `schema_version` | int | yes | `1` |
| `name` | string | yes | used for state directory and reports |
| `display_name` | string | no | |
| `source` | object | yes | see below |
| `tags` | object | yes | |
| `releases` | object | no | GitHub releases that are not releases of this project |
| `signing_key` | object | yes | |
| `assets` | object | yes | |
| `attestations` | object | no | omit if the project publishes none |
| `package_rebuild` | object | no | omit to skip package rebuilds |
| `images` | object | no | omit if there are no container images |
| `channels` | array | no | distribution channels that embed hashes |
| `watch` | object | no | tuning for `watch` |

### `source`

| Key | Notes |
|---|---|
| `repo` | GitHub `owner/name` |
| `default_branch` | branch `watch` reads the upstream release-signers directory from (to compare it with the pinned copy) |
| `git_url` | clone URL; defaults to `https://github.com/<repo>.git` |

### `tags`

| Key | Notes |
|---|---|
| `pattern` | Python regex with a named group `version`; tags not matching are not releases of this project and are not tracked (e.g. `bootnode-*`). A published GitHub release whose tag does not match is a `warn` in `watch` (`release-pattern`) unless `releases.ignore_tag_patterns` matches it |
| `signed_expected_after` | cutoff for signed annotated tags |
| `signers_dir` | required: directory **in this repository** (relative to the config file) holding the release-tag signers, e.g. `keys/nethermind-signers`. `verify` authenticates tags against this pinned copy only, never against anything fetched from GitHub |
| `upstream_signers_dir` | optional: the signers directory in the source repository (e.g. `.github/release-signers`). `watch` compares its git tree id on `default_branch` with the pinned copy: different = `fail` ("upstream release signers changed; review the change and update the pin"); absent upstream = `skipped` |
| `allowed_signers_file` | OpenSSH allowed-signers file inside `signers_dir` (default `allowed_signers`) |
| `gpg_keys_glob` | armored OpenPGP keys inside `signers_dir` (default `*.asc`) |
| `trusted_commits` | `{tag: full commit id}`: out-of-band trust for releases at or below `signed_expected_after` that have no signed tag. A pin is reviewed in this repository; the tag must resolve to the pinned commit (else `source-pin` fails) |

Rebuilds execute the release's own build recipe (Dockerfiles, build and archive scripts), so they
run only when the source is **authenticated**: the tag signature verified (`source: signed`), or
the tag is an unsigned legacy tag that resolves to its `trusted_commits` pin (`source: pinned`).
Otherwise nothing from the checkout runs: package and image rebuilds are reported as `skipped`
("source not authenticated"), and source-based channel checks are skipped too.

### `releases`

| Key | Notes |
|---|---|
| `ignore_tag_patterns` | list of Python regexes (searched, so anchor them with `^`). A published release whose tag does not match `tags.pattern` but matches one of these is skipped silently by `watch`: no `release-pattern` warning, not tracked. Use it for other artifacts published from the same repository (e.g. `^bootnode-`). It never applies to a tag that matches `tags.pattern`: client releases stay tracked |

### `signing_key` (release artifact signing key)

| Key | Notes |
|---|---|
| `fingerprint` | full 40-hex primary-key fingerprint; the trust anchor. Signatures count only if gpg's `VALIDSIG` names this primary key |
| `key_file` | optional armored key, path relative to the config file |
| `key_urls` | fallback key server URLs (*template* with `{fingerprint}` only) |

### `assets`

| Key | Notes |
|---|---|
| `template` | *template* for platform package names, must contain `{platform}` |
| `signature_suffix` | detached signature suffix (default `.asc`) |
| `checksums_file` / `checksums_signature` | e.g. `SHA256SUMS` / `SHA256SUMS.asc`, `sha256sum` format |
| `checksums_expected_after` | cutoff for the checksums file |
| `extra_allowed` | *templates* of other legitimate asset names (anything else raises `asset-unexpected`). Extras are not rebuilt: `verify` downloads them, checks their detached signature, and lists them in `coverage.extras` as `signed-not-rebuilt` (signed by the release key and in the signed checksums file; trusted) or `unsigned-not-rebuilt` / `unchecksummed-not-rebuilt` (the release is then not trusted, because e.g. the Nethermind ref-assemblies feed NuGet packages) |
| `extra_signed_expected_after` | cutoff for signed extras; at or below it an unsigned extra is `legacy` (still untrusted) |
| `platforms[]` | `{name, build_dir, expected_after?}`: asset platform, the matching directory in the package build output, and an optional cutoff for platforms added later |

### `attestations`

| Key | Notes |
|---|---|
| `signer_workflow` | `owner/repo/path/to/workflow.yml` passed to `gh attestation verify --signer-workflow` |
| `predicate_type` | default `https://slsa.dev/provenance/v1` |
| `expected_after` | cutoff for build provenance (zips and images) |
| `release_attestation` | `true` to check GitHub's immutable-release attestation via `gh release verify` (needs `GH_TOKEN`) |

### `package_rebuild`

| Key | Notes |
|---|---|
| `steps[]` | `{name, run: [argv *templates*], env?: {*templates*}, no_cache_flag?}` run in `{src_dir}`; must leave per-platform directories in `{out_dir}`. `no_cache_flag` (e.g. `--no-cache`) is appended when `verify --no-cache` is given. Steps are argv for host tools (`docker`); anything from the release must run inside a container, and containers that only copy output should use `--network none --user {uid}:{gid} --cap-drop ALL --security-opt no-new-privileges` |
| `archive` | optional `{image, run, cwd, mounts, env?, output_dir}`: the project's own archiving script, run **in a container** built from `image` (a Dockerfile in this repository, relative to the config file, base pinned by digest; e.g. `images/archive.Dockerfile` with bash and zip) with `--network none`, the invoking user, a read-only root filesystem, only the `env` variables (never the verifier's environment) and `mounts[]` (`{source, target, writable?}`; read-only unless `writable`, writable sources are recreated empty). `run` and `cwd` are paths inside the container. Run for every version above `reproducible_archives_expected_after`; its zips must be byte-identical to the published ones |
| `reproducible_archives_expected_after` | cutoff for byte-reproducible archives. Older releases are compared file-by-file (path, type, content hash, symlink target; exec bits as a warning) |
| `cleanup[]` | argv *templates* always run afterwards (e.g. remove the build image) |

### `images`

| Key | Notes |
|---|---|
| `registry` | `docker.io`, `ghcr.io`, ... (anonymous pull access is enough) |
| `reproducible_expected_after` | cutoff for reproducible images; at or below it a config-digest mismatch is `legacy` and a missing version tag or platform is `absent`. Above it a missing tag or platform is `missing`, which keeps the release untrusted |
| `buildkit_image` | the BuildKit image the release workflow builds with, pinned by digest (Nethermind: `moby/buildkit:v0.33.1@sha256:cec9f139…`, set in the release workflow through setup-buildx-action `driver-opts: image=...`, with buildx v0.38.0). Layer compression, rewrite-timestamp handling and the Dockerfile frontend change between BuildKit versions, so `verify` creates its docker-container builder with `--driver-opt image=<this>`; an existing builder (`--builder`) running any other image is an `error` (remove it with `docker buildx rm` so it is recreated). Update it together with the release workflow |
| `flavors[]` | see below |

Each flavor:

| Key | Notes |
|---|---|
| `name` | e.g. `default`, `chiseled` |
| `dockerfile` | path in the source tree |
| `repos` | image repositories carrying the flavor |
| `version_tag` | *template*, e.g. `{version}-chiseled`; version tags are treated as immutable |
| `latest_tags` | moving tags; each must point at a trusted verified release of this flavor (see `trusted` in the README). Pointing at a trusted release older than the newest trusted non-prerelease is a `warn` (a rollback to a release with known vulnerabilities) |
| `attestation_subject` | registry subject name used by the provenance attestation, e.g. `index.docker.io/nethermind/nethermind` |
| `platforms` | e.g. `["linux/amd64", "linux/arm64"]` |
| `build_args` | *templates* passed as `--build-arg` |
| `rewrite_timestamp` | pass `rewrite-timestamp=true` to the OCI exporter (default `true`) |
| `labels` | *templates* the published image config labels must equal |

Images are compared by **config digest** per platform: the config embeds `rootfs.diff_ids`
(uncompressed layer digests), so the comparison is independent of layer compression.

### `channels[]`

Common keys: `type`, `name` (default = type, must be unique), `platforms` (asset platforms the
channel should carry).

| `type` | Keys | What is checked |
|---|---|---|
| `homebrew` | `repo`, `branch` (the expected **default** branch), `path`, `template?`, `allowed_paths?` (default: `path` only) | the tap as brew loads it: its default branch must be `branch`, and every path of that branch's tree must be in `allowed_paths` (Nethermind: `nethermind.rb`, `README.md`, `LICENSE`, `CODEOWNERS`), so `Formula/`, `HomebrewFormula/`, `tap_migrations.json`, `formula_renames.json` or `cmd/` are a `fail`; the formula is read from that commit. Formula `version` (declared once) must be a release and not older than the newest trusted release (`warn` while that release was verified less than `watch.channel_grace_hours` ago, then `fail`); every `url`/`sha256` pair is checked when the release is tracked; with `template`, the whole formula is always compared (rendered exactly when the release hashes are known, else with only the URL/hash slots open). An unparsable formula is a `fail` |
| `ppa` | `owner`, `archive`, `source_package`, `legacy_uploads?` (`{version: sha256 of the .dsc}` for uploads made before verification existed, reviewed here), `file` (default `debian/postinst`), `source_dir?`, `changelog?`, `dsc_signing_fingerprint?`, `key_urls?` | **every** source the PPA publishes (all package names): another package name, or a version without a published GitHub release that is not in `legacy_uploads`, is a `fail` (apt installs the highest version and runs its maintainer scripts as root); a version of a published release that `verify` has not run for yet is `warn` ("pending verification", the publishing job uploads minutes after the release), and `fail` if its verification failed; per verified version: `url=`/`hash=` pairs in `file`, the `.dsc` upload signature (pinned key), `Format: 3.0 (native)`, exactly the `.dsc` plus one tarball (both listed in and matching the `.dsc`; a `.diff.gz` or any other file is `fail`); with `source_dir`, every file of the source package. Downloads and the tarball are capped (32 MiB compressed, 64 MiB per member, 256 MiB total, 10 000 members) and read as a stream; a source package over a cap or one that cannot be parsed (no `file`, `hash=` before `url=`, several top-level directories) is `fail` for that version, not an `error` |
| `winget` | `package_id`, `repo?` (default `microsoft/winget-pkgs`), `branch?`, `pinned_fields?` every version directory under the package is listed: a version that is not a release (not tracked, or newer than the newest release, or without a release tag) is a `fail`; for the newest `watch.channel_window` releases, a manifest of a release not verified yet is `warn` (pending verification; `fail` if its verification failed), and `InstallerUrl`/`InstallerSha256` per installer; with `pinned_fields`, the listed manifest keys. The manifest parser is not a YAML parser and fails closed: flow collections, block scalars, anchors/aliases/tags, multi-line or continued scalars, inline comments, tabs, several documents, a key set twice in an installer, or an installer URL/hash at the root instead of in every installer item make the manifest `fail` (`channel-content`) |

Every entry must use the canonical release download URL
(`https://github.com/<repo>/releases/download/<tag>/<asset>`) and the expected hash.

Hashes alone do not cover channels that ship installation logic: whoever controls the channel
could keep the URLs and hashes and add commands. Such content (`channel-content`) must equal
trusted content, and only the declared substitutions may differ:

- **Homebrew** `template`: path (relative to the config file) of the formula as reviewed in this
  repository, e.g. `templates/nethermind/homebrew.rb`, with `{{version}}`, `{{url:<platform>}}` and
  `{{sha256:<platform>}}` where the publishing job writes the release's values. The rendered
  template (verified hashes, else GitHub's digests) must equal the published formula byte for byte
  (only a trailing newline is normalized); a difference is `fail` with a diff. The tap lives
  outside the source repository, so a legitimate formula change needs a reviewed template update
  here.
- **PPA** `source_dir`: the directory of the *authenticated* source tree at the release tag that
  the publishing job packages (read from git objects, never executed). The source package must
  contain exactly these files with exactly this content, except: in `file`, the n-th line
  containing `url` / `hash` has everything from that word on replaced by `url=<download URL>` /
  `hash=<verified sha256>` of the n-th entry of `platforms` (the `awk` rewrite of the publishing
  job); and `debian/changelog` must be exactly the `changelog` lines (templates with `{version}`
  and `{date}`, an RFC 2822 date). `verify` stores the expected file hashes in the verification
  record so `watch` repeats the check on every run; without an authenticated source (or before
  `verify` ran) the check is `skipped`. Copies of the upload to other series are the same
  files and are checked once.
- **winget** manifests are declarative data: the installer is the verified zip itself and no
  install script is involved, so there is no template. `pinned_fields` maps manifest keys to the
  only values allowed anywhere in the manifest (e.g. `InstallerType: [zip]`,
  `RelativeFilePath: [nethermind.exe]`), so changing what gets run from the zip is a `fail`.

### `watch`

| Key | Default | Notes |
|---|---|---|
| `release_window` | 15 | newest releases **whose tag matches `tags.pattern`** tracked (assets, image version tags); the listing is paginated until that many match, so other releases cannot push them out. Published releases in that time range whose tag does not match are `warn` (`release-pattern`) unless `releases.ignore_tag_patterns` matches them. Every release with a verification record is always tracked, looked up by tag if needed; a verified release that is no longer published is `fail`. An unverified tracked release that drops out of the listing is looked up by tag: still published and unchanged but older than the window = evicted (`warn`, no longer tracked; verify it to keep it tracked); gone = `fail` ("published release disappeared"); lookup error = `error` (previous state kept). Set `GITHUB_TOKEN` so the per-tag lookups stay within the API rate limit |
| `channel_window` | 3 | newest non-prerelease versions checked in winget |
| `asset_upload_grace_seconds` | 0 | tolerance for `asset-after-publication` |
| `channel_grace_hours` | 24 | how long after a release is verified as trusted the Homebrew formula may still be at an older version (`warn`) before it is a `fail` |
