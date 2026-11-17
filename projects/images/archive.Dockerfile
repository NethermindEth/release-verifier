# Sandbox for a project's archive step (package_rebuild.archive): bash and Info-ZIP only. Built on
# the verifier host from this file; the base image is pinned by digest and zip by version, so
# nothing from the release under verification decides what this image contains. The step runs in
# it with no network, as the invoking user, with the checkout and build output mounted read-only.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

RUN apt-get update \
 && apt-get install -y --no-install-recommends zip=3.0-13+deb12u1 \
 && rm -rf /var/lib/apt/lists/*
