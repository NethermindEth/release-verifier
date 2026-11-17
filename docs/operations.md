# Operations

## Where to run it

The value of the verifier is independence. Run it on a machine and account that neither the
project's maintainers nor its CI provider control: a VM at a different cloud provider, owned by the
verifying organization, with its own alerting. Running on GitHub-hosted runners (see
`deploy/github-actions/`) shares a failure domain with the release pipeline; use it only as a
secondary signal.

Requirements:

| | `watch` | `verify --skip-rebuild` | `verify` (full) |
|---|---|---|---|
| Python 3.11+, git, gpg | yes | yes | yes |
| `gh` CLI 2.81+ | no | for attestations | for attestations |
| ssh-keygen (openssh-client) | no | for SSH-signed tags | for SSH-signed tags |
| Docker + buildx, `zip` | no | no | yes |
| Network | GitHub, Docker Hub, Launchpad, raw.githubusercontent.com | + keyserver | + NuGet/base images for the build |
| Disk | < 100 MB | ~1 GB | ~15 GB for packages, ~45 GB with images |
| Time (NMC, measured) | ~1-2 min | ~1-2 min (downloads ~0.6 GB) | ~18 min (packages 5 min + 4 images × 3 min) |

No Nethermind secret is needed. `GITHUB_TOKEN` (any token, no scopes) is optional: it raises the
GitHub API rate limit from 60/h and enables the immutable-release attestation check
(`gh release verify`).

### Resource needs for an NMC rebuild

Measured on NMC 2.2.0 (16 cores, 28 GB RAM, ~8 MB/s download), `verify --no-cache`:

- Package rebuild: one `docker build` of `scripts/build/Dockerfile` (all six platforms): 304 s,
  ~15 GB of disk for the SDK image, NuGet packages and build output.
- Image rebuild: one buildx build per flavor and platform (default and chiseled × amd64 and arm64):
  171-186 s each. The .NET build stage cross-compiles on the build platform, so arm64 needs no
  emulation for the build itself. The `docker-container` builder's cache grew to ~31 GB for the
  four builds.
- Whole run: 18 min 21 s. Without `--no-cache` later runs reuse the cache and are much faster, at
  the price of trusting the local cache; use `--no-cache` for the authoritative run of a new release.
- The verifier needs a `docker-container` buildx builder (created as `release-verifier` if missing)
  because the OCI exporter with `rewrite-timestamp` is not available on the default `docker` driver.
  It runs the BuildKit image pinned in `images.buildkit_image` (the same one the release workflow
  uses; for NMC `moby/buildkit:v0.33.1@sha256:cec9f139…`), because image bytes depend on the
  BuildKit version. A new builder is created with `--driver-opt image=<pin>`; an existing builder
  running another image makes the image rebuild an `error`. After a pin update in the config,
  run `docker buildx rm release-verifier` once so it is recreated. The builder is checked once per
  run, before the first image build; do not reconfigure it during a run.
- Nothing from the release runs on the host. The package export runs as the invoking user with
  `--network none`, so its output is not root-owned. The archive step runs in a local image built
  from `projects/images/archive.Dockerfile` (`release-verifier-archive:<hash>`, built once, needs
  network for `apt-get` at build time only), with no network, the invoking user, a read-only root
  and only the declared environment. Downloads, checkouts and rebuild output are removed after
  each run unless `--keep-work` is given. Prune caches after runs:
  `docker buildx prune --builder release-verifier -af` and `docker builder prune` (package builds
  use the default builder).

## Install

### Plain host (systemd)

```sh
sudo useradd --system --home /var/lib/release-verifier release-verifier
sudo git clone https://github.com/NethermindEth/release-verifier.git /opt/release-verifier
sudo install -d -m 0700 /etc/release-verifier
sudo install -m 0600 /dev/null /etc/release-verifier/env   # alert sinks, optional GITHUB_TOKEN
sudo cp /opt/release-verifier/deploy/systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now release-verifier-watch.timer
# full verification of a release (the instance name is the tag)
sudo systemctl start release-verifier-verify@2.2.0
```

`verify` needs Docker; membership in the `docker` group is root-equivalent, so keep the verifier
host single-purpose.

### Container

```sh
docker build -t release-verifier .
# watch: no Docker access needed
docker run --rm -v /var/lib/release-verifier:/var/lib/release-verifier release-verifier watch --project nethermind
# verify: drives the host daemon; mount the work dir at the SAME path inside and outside,
# because bind-mount sources in the rebuild steps are resolved by the host daemon.
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /var/lib/release-verifier:/var/lib/release-verifier \
  release-verifier verify --project nethermind --tag 2.2.0
```

### Kubernetes

`deploy/kubernetes/cronjob.yaml` runs `watch` every 15 minutes with state on a PVC. Run `verify`
on a VM; giving a pod the node's Docker socket hands it the node.

## State

`--state DIR` (or `RELEASE_VERIFIER_STATE`) holds, per project:

| Path | Content | Loss impact |
|---|---|---|
| `snapshot.json` | baseline for the next `watch` diff | next run re-baselines; changes in between go unnoticed |
| `snapshots/` | history (last 200) | forensics only |
| `verified.json` | per-tag verification record: commit, verified hashes, image digests, outcome, per-artifact `coverage`, `trusted`, trusted channel references | `latest` checks fall back to "unverified" warnings; re-run `verify` |
| `reports/` | every JSON report | forensics only |
| `alerts-sent.json` | alert de-duplication | duplicate alerts |
| `cache/` | pinned keys, content-addressed manifests | refetched |
| `work/` | shallow source clone and scratch space (default location) | refetched |

Back up `verified.json` and `snapshot.json`; they are small. Treat the state directory as
security-relevant: an attacker who can write it can hide changes. Keep it on the verifier host,
not in storage the release pipeline can reach.

## Alerts

Configure via environment (never logged):

| Variable | Effect |
|---|---|
| `RELEASE_VERIFIER_SLACK_WEBHOOK` | Slack incoming webhook; one message with the new findings |
| `RELEASE_VERIFIER_WEBHOOK_URL` | generic POST of `{"new_findings": [...], "report": {...}}` |
| `RELEASE_VERIFIER_WEBHOOK_TOKEN` | optional bearer token for the generic webhook |
| `RELEASE_VERIFIER_ALERT_ON` | statuses that alert (default `fail,error,warn`) |
| `RELEASE_VERIFIER_ALERT_REPEAT_HOURS` | re-alert identical findings after N hours (default 24) |

If an alert sink fails, the run exits 2 even when the checks passed, so the failure is visible.
Systemd marks the unit failed on exit 1 or 2; hook that into existing unit-failure monitoring as a
backstop for the webhooks.

## Handling findings

| Status | Meaning | Action |
|---|---|---|
| `fail` | compromise-class evidence: moved/deleted tag, replaced asset, bad signature, rebuild mismatch, re-pointed version image, channel hash mismatch, channel content differing from the trusted template/source, `latest` pointing at an unknown image | Treat as an incident. Tell users to stop installing the release (warn in the project's channels), contact the project's security contact, preserve the report and `snapshots/`. A `channel-content` failure on the Homebrew formula can also be a legitimate formula change: confirm it with the project, then update the pinned template in `projects/templates/` through a reviewed change |
| `error` | the check could not run (network, rate limit, Docker) | re-run; persistent errors mean you are blind |
| `warn` | needs a human (new release to verify, asset changed after publication, `latest` pointing at an unverified release or at one verified without full coverage) | usually: run (a full) `verify` for the release |
| `legacy` | control not yet adopted for that release | none |
| `skipped` / `info` | not applicable / informational | none |

A `watch` diff that contains `fail` does **not** advance the baseline, so the finding repeats on
every run until someone investigates and runs `watch --accept`.

Routine flow: `watch` flags a new release (`warn`), the operator (or automation) runs
`verify --tag <tag>`; after a passing **full** verify (`trusted: true`), `watch` accepts `latest`
moving to that release. Runs with skip/subset options pass but leave `latest` at `warn`. Releases
that cannot be rebuilt identically (e.g. NMC 2.2.2 and earlier images, built before `rewrite-timestamp`) stay
untrusted; that `warn` is the honest state for them.

## Exit codes

`0` no compromise-class finding (legacy/skipped/info/warn allowed), `1` at least one `fail`,
`2` tool/infra error (or alert delivery failure) without any `fail`.
