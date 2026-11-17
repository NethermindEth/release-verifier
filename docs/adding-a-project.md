# Adding a project

The core code knows nothing about Nethermind; a project is a JSON file in `projects/`
([schema](config.md)). Onboarding is mostly about making the project's release process
*verifiable*, then describing it.

## Prerequisites the project must meet

A verifier can only prove what the release process makes provable. Before onboarding, the project
needs:

1. **Signed, annotated release tags.** Tags must be annotated (`git tag -s`) and signed with SSH or
   OpenPGP by a key listed on the default branch (e.g. `.github/release-signers/allowed_signers` and
   `<login>.asc`). The release workflow must refuse to build an unsigned tag and must read the
   signer list from the default branch, never from the tag. Why: a tag created by a stolen GitHub
   token or a compromised CI cannot be signed by a maintainer's hardware-backed key.
2. **A pinned artifact-signing key.** Every published artifact and the checksums file get a
   detached OpenPGP signature from one release key whose full fingerprint is published out of band
   (release notes, website) and pinned in the config.
3. **A `SHA256SUMS` file** (`sha256sum` format, sorted, signed) listing every downloadable package.
4. **A reproducible build recipe** runnable by a third party from a clean checkout: a container
   build with pinned base images (by digest), locked dependencies, `SOURCE_DATE_EPOCH` from the
   commit timestamp, and no network-dependent or time-dependent output. Archives must be
   reproducible too (sorted entries, fixed timestamps/modes, `TZ=UTC`, no extra attributes), so a
   rebuilt zip is byte-identical to the published one. Document the exact commands; they go into
   `package_rebuild.steps` and `package_rebuild.archive`.
5. **Reproducible images** if you publish containers: BuildKit with `SOURCE_DATE_EPOCH`,
   `rewrite-timestamp=true`, base images pinned by digest, deterministic labels (e.g. the OCI
   `created` label derived from the commit time, not wall-clock time).
6. **Immutable version tags** in every registry (never re-push `X.Y.Z`); only `latest`-style tags
   move, and only to a release image.
7. **Build provenance** (recommended): `actions/attest-build-provenance` for packages and images
   (`push-to-registry: true`), plus GitHub immutable releases.
8. **Distribution channels** (Homebrew, PPA, winget, ...) must take hashes from the released assets
   and point at the canonical GitHub download URLs.

Releases made before a control existed are fine: set the matching `*_expected_after` cutoff to the
last release without it, and those gaps are reported as `legacy` instead of failures. Unsigned
legacy tags are not rebuilt (the verifier never runs unauthenticated build recipes) unless their
commit is pinned in `tags.trusted_commits` after an out-of-band check, reviewed in this repository.

## Steps

1. Copy `projects/nethermind.json` to `projects/<name>.json` and edit:
   - `source.repo`, `source.default_branch`;
   - `tags.pattern` (e.g. `^v(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)$` for `v`-prefixed tags);
   - `signing_key.fingerprint` (and optionally commit the public key under `projects/keys/`);
   - `tags.signers_dir`: copy the project's signers directory (e.g. `.github/release-signers/`,
     `allowed_signers` plus `<login>.asc`) to `projects/keys/<name>-signers/` after checking the
     keys out of band; tags are authenticated against this copy only. Set
     `tags.upstream_signers_dir` so `watch` fails when the upstream directory diverges;
   - `assets.template` and `assets.platforms` (`build_dir` = where your build puts each platform);
   - `attestations.signer_workflow` (the workflow that calls `attest-build-provenance`);
   - `package_rebuild.steps` and `archive`: the documented reproducible recipe, as argv lists;
   - `images.flavors` (or remove `images`), `channels` (or remove);
   - cutoffs for controls the project adopted recently.
2. Validate: `bin/release-verifier check-config --project <name>`.
3. Dry-run on the newest release without rebuilds:
   `bin/release-verifier verify --project <name> --tag <tag> --state /tmp/rv --skip-rebuild`.
   Every `fail` here is either a config mistake or a real problem; fix the config until only
   expected `legacy` findings remain.
4. Run the full verification once on dedicated hardware and record the resource needs in
   `docs/operations.md`.
5. Add `watch` for the project to the deployment (one more timer/CronJob, same state volume).

## When the generic model does not fit

Prefer extending the schema with a generic concept (a new channel `type`, a new comparison mode)
over project-specific code. If a project needs a step the schema cannot express, add the minimal
mechanism to the core with a unit test and document it in `docs/config.md`; keep the project's
specifics in its JSON file.
