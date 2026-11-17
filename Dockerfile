# Release verifier image. Every input is pinned by digest or checksum so the verifier itself is
# reproducible and does not silently pick up a compromised dependency.
#
# The container drives the HOST Docker daemon for rebuilds (bind-mount /var/run/docker.sock).
# Bind-mount sources are resolved by the host daemon, so mount the work directory at the SAME
# absolute path inside and outside the container (see docs/operations.md).

FROM docker:28-cli@sha256:625d9431a9f54c5a2bc90f24f0e1c3d55b1349fd857dd85035f98c2c9acbdd4d AS docker-cli

FROM python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258

ARG TARGETARCH
ARG GH_VERSION=2.102.0
ARG GH_SHA256_AMD64=bb766f710eef8ede859c18578c72c327597cd4c8a85b06001b1f3843c6019386
ARG GH_SHA256_ARM64=7862c86c72f43df3a2d93ddde6f473285b4e2af61b494849846827e513ef6484

# git: tags and checkouts; gnupg: signatures; openssh-client: ssh-keygen for SSH-signed tags;
# zip: the project's reproducible archive step; curl: fetching gh.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git gnupg openssh-client zip \
 && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    case "$TARGETARCH" in amd64) sum=$GH_SHA256_AMD64 ;; arm64) sum=$GH_SHA256_ARM64 ;; *) echo "unsupported $TARGETARCH"; exit 1 ;; esac; \
    curl -fsSL -o /tmp/gh.tgz "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    echo "$sum  /tmp/gh.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gh.tgz -C /tmp; \
    install -m 0755 "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh" /usr/local/bin/gh; \
    rm -rf /tmp/gh*

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=docker-cli /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx

WORKDIR /opt/release-verifier
COPY release_verifier ./release_verifier
COPY projects ./projects

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RELEASE_VERIFIER_STATE=/var/lib/release-verifier

ENTRYPOINT ["python", "-m", "release_verifier"]
CMD ["--help"]
