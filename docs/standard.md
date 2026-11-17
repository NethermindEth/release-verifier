# Nethermind release security standard

This applies to every Nethermind project that ships binaries or images to users.

The goal is that anyone can check two things about a published artifact: that it was built from a specific reviewed commit, and that nobody changed it afterwards. "Anyone" includes users and independent parties such as the Ethereum Foundation. A compromised build server, CI secret, registry account, or package-repository key must be detectable from outside Nethermind's infrastructure.

## Threat model

| Attacker controls | Detected by |
|---|---|
| A maintainer account or branch, but no reviewer | Signed release tag checked against a signer list on the protected default branch; environment approval. The independent verifier authenticates tags against its own reviewed copy of the signer list and fails when the upstream list changes |
| The release workflow on a branch | Environment deployment-branch policy and required reviewers gate every signing and publishing secret |
| The CI runner or build server | Independent rebuild on separate infrastructure (signatures and attestations would still be valid) |
| Docker Hub, PPA, Homebrew or winget credentials | The independent verifier compares every channel against the signed `SHA256SUMS` and rebuilt image config digests |
| The GitHub repository itself | Only the independent rebuild from a tag the verifier pinned on first sight |
| A third-party action or base image update | Actions pinned to commit SHAs, base images pinned by digest, lock files in locked mode |

Signatures and attestations prove *who* published an artifact. Only reproducible builds, re-run by someone else, prove *what* it contains.

## Required controls (MUST)

### Source
1. Default and release branches are protected and require review.
2. Releases are cut from an **annotated, signed tag** (SSH or OpenPGP) created by a listed release signer. The signer list lives in the repository and is covered by CODEOWNERS. The release workflow reads it **from the default branch**.
3. A tag ruleset protects release tags: only release managers create them, and update and deletion are blocked.

### Build
4. Builds run in a container whose base image is pinned by digest.
5. Dependencies are locked with content hashes and restored in locked mode (`packages.lock.json` + `--locked-mode`, `Cargo.lock` + `--locked`, `go.sum`). Package sources are restricted (e.g. NuGet `packageSourceMapping`).
6. Builds are **reproducible**: rebuilding the tag on a different machine yields the same `SHA256SUMS` and the same image config digests. That requires:
   - `SOURCE_DATE_EPOCH` set to the commit time,
   - archives with sorted entries, fixed timestamps and no host metadata,
   - images exported with `rewrite-timestamp=true`.
7. Third-party GitHub Actions in release workflows are pinned to full commit SHAs. Workflow `permissions` are least-privilege per job.

### Signing and publishing
8. Signing keys and publishing credentials live only in **environment secrets** of a protected environment, with no repository-level copies. The environment requires reviewers, prevents self-review, does not let admins bypass it, and limits deployment to protected branches and tags.
9. Every release publishes `SHA256SUMS`, detached signatures for it and for every artifact, and Sigstore build-provenance attestations (`actions/attest-build-provenance`) for files and images.
10. Published releases are **immutable** (GitHub immutable releases). Version image tags are immutable too (Docker Hub immutable tags, e.g. `^[0-9]+\.[0-9]+\.[0-9]+.*$`). Only floating tags such as `latest` move.
11. Downstream channels (PPA, Homebrew, winget, …) take their hashes from the signed `SHA256SUMS`.
12. The signing key fingerprint is published in the release notes and the docs. The public key is on `keys.openpgp.org` and served via WKD.

### Monitoring
13. The project is onboarded to the independent release verifier ([adding-a-project.md](adding-a-project.md)), configured with the pinned key fingerprint, the signer list location and the rebuild recipe.
14. At least one verifier instance runs on infrastructure Nethermind does not administer (e.g. operated by the EF). `watch` runs at least every 15 minutes, and `verify` runs for every new release.
15. A verifier `fail` finding pages the security on-call, and the affected channel is paused until the finding is resolved.

## Recommended controls (SHOULD)
- Hardware-backed release keys (HSM or YubiKey) instead of key material in CI secrets; subkeys with expiry.
- Platform code signing: Windows Authenticode, macOS Developer ID + notarization.
- SBOMs attached to releases and images; vulnerability gate (Trivy) on release images.
- OpenSSF Scorecard on release repositories.
- Automated updates for pinned actions (Dependabot/Renovate) so SHA pins don't go stale.
