# release-verifier

An independent verifier for software releases, built for Nethermind projects and meant to be run
by a third party (for example the Ethereum Foundation) on infrastructure Nethermind does not
control. It detects a compromised build server, stolen Docker Hub / PPA / signing credentials, and
tampered release assets, by checking what was published against signatures pinned out of band and
against an **independent rebuild from source**.

- Client-agnostic core; each project is a JSON file in [`projects/`](projects/) (see
  [docs/config.md](docs/config.md)). Nethermind (NMC) is the first one;
  [docs/adding-a-project.md](docs/adding-a-project.md) covers onboarding other client teams.
- Python 3.11+ standard library only. Shells out to `git`, `gpg`, `docker buildx` and `gh` (only for
  `gh attestation verify` / `gh release verify`). Everything else is plain HTTPS; no token needed.
- Runs on Linux (rebuilds need Docker and run as the invoking POSIX user). On other systems the
  unit tests that need symlinks or POSIX user ids are skipped.
- Needs no Nethermind secret.
- [docs/standard.md](docs/standard.md) is the Nethermind release security standard this tool enforces from the outside.

## Requirements

| | `watch` | `verify` (full) |
|---|---|---|
| OS | Linux (x86-64 or arm64) | Linux x86-64 (rebuild timings below are on x86-64) |
| Software | Python 3.11+, git, gpg | + `gh` 2.81 or newer (attestations, `gh release verify`), ssh-keygen, Docker Engine with buildx and the `docker-container` driver, `zip` |
| CPU / RAM | any | 8+ cores, 16+ GB RAM (measured: 16 cores, 28 GB) |
| Disk | < 100 MB | ~15 GB for packages, ~45 GB with image rebuilds |
| Time (NMC) | 1-2 min | ~5 min packages, ~3 min per image flavor × platform; ~18 min in total on 16 cores |
| Network | GitHub, Docker Hub, Launchpad | + keyserver, NuGet and base-image registries for the build |

The [`Dockerfile`](Dockerfile) bundles Python, git, gpg, ssh-keygen, `gh` and the Docker CLI with
buildx, all pinned; `verify` in the container still needs the host's Docker daemon. No Nethermind
secret is needed; a `GITHUB_TOKEN` with no scopes is optional (rate limits and the
immutable-release check). Details in [docs/operations.md](docs/operations.md).

## Quick start

Bare (from a clone; no `pip install` needed, the package has no dependencies):

```sh
git clone https://github.com/NethermindEth/release-verifier.git && cd release-verifier
export RELEASE_VERIFIER_STATE=$PWD/state

bin/release-verifier check-config --project nethermind

# Cheap: snapshot tags, releases, image digests and channel hashes; diff against the last run.
bin/release-verifier watch --project nethermind

# Full: signatures, checksums, attestations, independent package + image rebuilds, channels.
bin/release-verifier verify --project nethermind --tag 2.2.2
# Faster variants
bin/release-verifier verify --project nethermind --tag 2.2.2 --skip-rebuild
bin/release-verifier verify --project nethermind --tag 2.2.2 --platforms linux-x64 --image-platforms linux/amd64

python3 -m unittest        # unit tests (no network, no Docker)
```

Container (state on a named volume; `watch` needs no Docker socket):

```sh
docker build -t release-verifier .
docker volume create release-verifier-state
docker run --rm -v release-verifier-state:/var/lib/release-verifier release-verifier check-config --project nethermind
docker run --rm -v release-verifier-state:/var/lib/release-verifier release-verifier watch --project nethermind
```

For `verify` in the container (host Docker socket, work directory at the same path inside and
outside) see [docs/operations.md](docs/operations.md#container).

`python -m release_verifier ...` works the same as `bin/release-verifier ...`. After
`pip install .` the `release-verifier` command is on `PATH`; point it at the configs with
`RELEASE_VERIFIER_PROJECTS_DIR=<repo>/projects` or pass a config path to `--project`.

### CLI

```
release-verifier watch  --project P [--state DIR] [--accept] [--json PATH|-] [--no-alerts]
release-verifier verify --project P --tag T [--state DIR] [--work-dir DIR]
                        [--skip-rebuild] [--skip-image-rebuild]
                        [--platforms linux-x64 ...] [--image-platforms linux/amd64 ...]
                        [--flavors default chiseled] [--builder NAME] [--no-cache] [--keep-work]
                        [--json PATH|-] [--no-alerts]
release-verifier check-config --project P
```

`--platforms` limits which packages are compared against the rebuild; every package is still
downloaded and signature-checked.

**Exit code vs trust.** The skip and subset options (`--skip-rebuild`, `--skip-image-rebuild`,
`--platforms`, `--image-platforms`, `--flavors`) still exit 0 when nothing fails, but the run
does not establish trust. `verify` records per-artifact coverage in `verified.json`
(`coverage.source`: `signed`/`pinned`/`unauthenticated`; `coverage.packages` per platform:
`identical`, `contents-match` (legacy releases only), `bytes-differ` (every file matches but the
zip is not byte-identical although the release is above the reproducible-archive cutoff),
`mismatch`, `skipped`, `error`, `absent`; `coverage.images` per
`<repo>:<tag>@<platform>`: `identical`, `legacy-mismatch`, `mismatch`, `skipped`, `error`,
`absent` (legacy releases only), `missing` (tag or platform not published although the release
is above `images.reproducible_expected_after`; not trusted), `unexpected` (a runnable platform
the recipe does not build; `fail`), `malformed`; `coverage.extras` per allowed extra asset (e.g. ref-assemblies, never rebuilt):
`signed-not-rebuilt`, `unsigned-not-rebuilt`, `unchecksummed-not-rebuilt`; `coverage.channels`)
and derives `trusted`: outcome pass, authenticated source, every
published package rebuilt and matching (byte-identical above the cutoff; file-by-file only for
legacy archives), every extra asset signed and in the signed checksums, every published image flavor × platform rebuilt
identical. `watch` reports `latest*` as `pass` only for a trusted release; a passing but untrusted
record is a `warn` naming the missing coverage (records written before coverage tracking count as
untrusted). The `coverage` result of each `verify` run says which it is.

## Running an instance

For a third party (for example the Ethereum Foundation) running its own instance:

1. Run `watch` every 15 minutes or more often, on a machine and account Nethermind does not
   control ([docs/operations.md](docs/operations.md#where-to-run-it) has systemd, Kubernetes and
   container examples). Keep the state directory on that machine.
2. When `watch` reports a new release (`warn`), run a full `verify --tag <tag>` without skip or
   subset options. Use `--no-cache` for the authoritative run.
3. Route alerts (`RELEASE_VERIFIER_WEBHOOK_URL` or `RELEASE_VERIFIER_SLACK_WEBHOOK`) and unit
   failures (exit 1 or 2) to someone who will act on them.
4. Review every change to this repository before pulling it: the pinned keys, signer list,
   `trusted_commits` and channel templates are what your instance trusts. Prefer running from your
   own fork and pulling upstream changes through review.

Reading results:

| Status | Means | Do |
|---|---|---|
| `fail` | compromise-class evidence: bad or missing signature where one is required, rebuild mismatch, moved tag, replaced asset, channel serving other bytes | Treat as an incident: preserve `<state>/<project>/reports/` and `snapshots/`, contact Nethermind (below), warn users if confirmed |
| `error` | a check could not run (network, rate limit, Docker); inconclusive | re-run; a persistent error means the instance is blind |
| `warn` | needs a human: a new release to verify, `latest` pointing at a release not yet fully verified, an upload not yet checked | usually: run a full `verify` |
| `legacy` | the control was adopted after this release (for NMC: everything up to 2.2.2 has no signed tag, `SHA256SUMS`, attestations, windows-arm64 package or reproducible images) | none |
| `pass` / `info` / `skipped` | checked and fine / informational / not applicable | none |

Contact for findings: **`security@nethermind.io`**. Include the JSON report of the
failing run. Do not open a public GitHub issue for a `fail` before Nethermind has confirmed or
ruled out a compromise.

## What it checks, and what each check proves

| Check | Proves | Does not prove |
|---|---|---|
| **Signed tag** (`signed-tag`, `tag-binding`): annotated tag, signed by a key pinned in this repository (`projects/keys/<project>-signers/`, a reviewed copy of the project's `.github/release-signers/`), peels to the release commit; the signed tag object's `tag` header is the ref name and it tags the commit directly, and the version is newer than every release verified before (re-verifying the same tag at the same commit is allowed) | A maintainer holding a signing key approved this exact commit as this release. A stolen GitHub token, a compromised CI, or a push to the source repository's default branch cannot forge it: the signer list is read from this repository, not from GitHub. An old signed tag copied to a new name, or a signed tag re-released under a lower version, is a `fail` and the source counts as unauthenticated. | That a pinned maintainer key was not compromised; that the commit is benign. |
| **Release signers** (`release-signers`, `watch`): git tree id of the upstream signers directory on the default branch vs the pinned copy | A signer change upstream is noticed and needs a reviewed pin update here before `verify` accepts the new signer. | That the upstream change is legitimate (review it). |
| **Source authentication** (`source-pin`, report `meta.source`): the source counts as authenticated only with a valid tag signature (`signed`) or, for unsigned legacy releases, a commit pinned in `tags.trusted_commits` (`pinned`) | Rebuilds run the release's own Dockerfiles and scripts; they run **only** for authenticated source, and even then only inside containers (BuildKit, or `docker run --network none --user <uid>:<gid> --cap-drop ALL` for the export and archive steps, the archive image built from a Dockerfile in this repository): nothing from the checkout runs on the verifier host or sees its environment. Otherwise rebuilds are `skipped` ("source not authenticated") and nothing from the checkout executes. | A pin is only as good as the review of the pinning change in this repository. |
| **GPG signatures** (`gpg-signature`): every package and `SHA256SUMS` signed by the pinned release key (`VALIDSIG` must name the pinned primary fingerprint) | The holder of the release key signed these bytes. Catches assets replaced by someone with only GitHub write access. | The key lives in CI secrets: a compromised release workflow can sign anything. Signatures alone do not prove the bytes came from the tagged source. |
| **Checksums** (`checksums`, `asset-digest`): `SHA256SUMS` vs downloaded bytes vs GitHub's per-asset digest | All three views of the release agree; no asset was swapped after signing. | Anything about how the bytes were produced. |
| **Build provenance** (`provenance`, `image-provenance`): `gh attestation verify --signer-workflow .../release.yml` with bundles fetched over HTTPS | The artifact digest was attested by a run of the expected workflow in the expected repo (Sigstore, transparency-logged). | That GitHub, the runner, or the workflow's dependencies were uncompromised: a poisoned build inside the right workflow gets a valid attestation. **This is why the independent rebuild matters.** |
| **Immutable-release attestation** (`release-attestation`, needs `GH_TOKEN`) | GitHub attests the tag commit and asset digests at publication; assets cannot be changed afterwards. | Same trust in GitHub as above. |
| **Independent package rebuild** (`package-rebuild`) | The published binaries are exactly what the tagged source produces with the documented recipe, on hardware the attacker does not control. For reproducible archives the zip bytes must match; for legacy releases every file (path, type, content, symlink target) must match. | That the source itself is benign (review is a separate concern), or that the pinned toolchain base images are benign (they are pinned by digest in the source, so a change is visible in review). |
| **Image index** (`image-index`, `verify` and `watch`): platforms are normalized (`arm64/v8` = `arm64`, `amd64/v2..v4` = `amd64`); a platform listed twice, a runnable platform the recipe does not build, or an index/manifest the client cannot parse is a `fail` for that tag. A version tag that `verify` found absent and that appears later is a `fail` in `watch` | A runtime on any host pulls only an image the rebuild covers; a variant or extra descriptor cannot slip an unchecked image past the comparison. | That the covered images are benign (that is the rebuild's job). |
| **Image rebuild** (`image-rebuild`): per-platform image **config digest** equality | The image layers (`rootfs.diff_ids`) and config equal an independent build of the tag. Robust to layer compression. | Same as above. Releases before images were built with `rewrite-timestamp` cannot match and are reported as `legacy`. |
| **Image labels** (`image-labels`) | The image claims the right revision/version. | Cheap consistency check only; labels are attacker-controlled. |
| **Channels** (`channel-hash`, `channel-content`, `ppa-upload-signature`, `ppa-source-integrity`): Homebrew formula, PPA source package, winget manifest | Package managers download the verified zips (canonical URL + verified sha256). The executable channel content equals trusted content except the declared substitutions: the formula equals the template pinned in this repository, every file of the PPA source package equals the authenticated source tree at the tag (`scripts/build/ppa`), winget's installer type and nested executable equal pinned values. PPA uploads are signed by the pinned key and the source matches its `.dsc`. | That the channel's own infrastructure (Launchpad, Homebrew tap, winget repo) serves this content to every user. A legitimate formula change shows up as a `fail` until the pinned template is updated (see [docs/config.md](docs/config.md#channels)). |
| **Watch** (`tag`, `release`, `release-asset`, `image-tag`, `latest-tag`, `channel-content`, ...) | Mutable state did not change after the fact: tags not moved/deleted, assets not added/replaced/removed after publication, version image tags never re-pointed, `latest*` only pointing at a trusted (fully rebuilt and matching) verified release, channel hashes and content matching. | Anything between two snapshots that was reverted before the next one (run `watch` frequently). |

Threats in scope: compromised build runner or release workflow, stolen Docker Hub credentials,
stolen PPA/Launchpad credentials, stolen release signing key, a GitHub token able to edit releases
or push tags, tampered distribution manifests. Out of scope: malicious source code that passes
review, compromise of the verifier host itself, and attacks on end users' package-manager
infrastructure.

### What a third-party instance proves, and what it does not

A passing, `trusted` full `verify` run on infrastructure Nethermind does not control proves that
the published packages and images are what the signed (or pinned) tag builds into with the
project's own recipe, and that the channels serve those bytes. `watch` adds that this stayed true
at each snapshot.

It does not prove:

- **That the source is benign.** A malicious change that passes Nethermind's review is rebuilt
  faithfully and passes.
- **That users were safe before the run.** The verifier detects; it does not block. Between
  publication and the first `verify`, and between two `watch` snapshots, users can download a
  tampered artifact. Alert latency is the run interval.
- **More than this repository's pins.** Signer keys, the release key fingerprint,
  `trusted_commits` and channel templates are read from this repository. Whoever can change it
  (today: Nethermind) can change what passes. Run from a fork you control and review pin changes.
- **Anything strong about legacy releases.** Up to NMC 2.2.2 the source is authenticated only by a
  reviewed commit pin, packages are compared file by file (the zips are not byte-reproducible),
  and there are no attestations or `SHA256SUMS`. Images built before `rewrite-timestamp` cannot
  be rebuilt identically (`legacy`), which leaves the release untrusted, so `latest` pointing at
  one stays a `warn`.
- **That the toolchain is clean.** The rebuild uses the base images and NuGet packages pinned in
  the source. A compromised pinned dependency produces the same bytes on both sides; reviewing
  those pins is part of reviewing the source.
- **That the channel infrastructure serves everyone the same bytes.** The verifier sees what
  Launchpad, the Homebrew tap, winget and Docker Hub serve to it.
- **That the verifier host is intact.** Anyone who can write the state directory or the checkout
  can hide findings.

## Outputs

Every run prints a human summary (findings ordered by severity; `-v` also lists passing checks)
and writes a JSON report to `<state>/<project>/reports/` (and to `--json PATH`, or stdout with
`--json -`):

```json
{
  "schema_version": 1, "command": "verify", "project": "nethermind", "target": "2.2.0",
  "started_at": "...", "finished_at": "...", "exit_code": 0,
  "counts": {"pass": 24, "legacy": 14, "fail": 0, "error": 0, "...": 0},
  "meta": {"commit": "...", "durations_s": {"...": 0}, "rebuild": {"packages_s": 0}},
  "results": [{"check": "gpg-signature", "status": "pass", "subject": "<asset>", "message": "...", "details": {}}]
}
```

Statuses: `pass`, `info`, `legacy` (control adopted after this release), `skipped`, `warn`
(needs a human), `fail` (compromise-class), `error` (tool/infra failure; the check is
inconclusive).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | no compromise-class finding (`legacy`, `skipped`, `info`, `warn` allowed) |
| 1 | at least one `fail` |
| 2 | tool/infra error (or alert delivery failure) and no `fail` |

## Alerts

Optional, via environment: `RELEASE_VERIFIER_SLACK_WEBHOOK`, `RELEASE_VERIFIER_WEBHOOK_URL`
(JSON POST, optional `RELEASE_VERIFIER_WEBHOOK_TOKEN`). Details in
[docs/operations.md](docs/operations.md#alerts).

## Deployment

[docs/operations.md](docs/operations.md): where to run it, state storage, alert handling and
resource needs. Examples: [`Dockerfile`](Dockerfile) (pinned by digest),
[`deploy/systemd/`](deploy/systemd/), [`deploy/kubernetes/cronjob.yaml`](deploy/kubernetes/cronjob.yaml),
[`deploy/github-actions/release-verifier.yml`](deploy/github-actions/release-verifier.yml)
(reduced independence; read the warning in the file).

## Repository layout

```
release_verifier/   core (stdlib only)
  cli.py            argument parsing, report emission, alerts
  watch.py          snapshot collection, single-snapshot evaluation, snapshot diff
  verify.py         full verification of one tag
  rebuild.py        package/image rebuilds, zip-vs-tree and OCI comparisons
  channels.py       Homebrew / PPA / winget fetch, parse, evaluate
  registry.py       anonymous OCI registry client
  trust.py          per-artifact coverage and the trust `watch` grants a verified release
  gitops.py gpg.py attest.py github.py net.py checksums.py versions.py state.py alerts.py results.py config.py
projects/           project configs (+ pinned public keys, pinned channel templates)
docs/               config schema, onboarding, operations
deploy/             systemd, Kubernetes, GitHub Actions examples
tests/              unittest suite with real NMC 2.2.0 fixtures
```

## License

LGPL-3.0-only; see [LICENSE](LICENSE) and [COPYING](COPYING).
