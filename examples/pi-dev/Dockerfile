# syntax=docker/dockerfile:1
# Guest development tools only. TraceWard supplies gVisor and observation code.
FROM node:22.20.0-bookworm-slim@sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e AS node
FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm

ARG PI_VERSION=0.85.1
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
      bash build-essential ca-certificates curl git jq ripgrep unzip \
 && rm -rf /var/lib/apt/lists/* \
 && npm install --global "@earendil-works/pi-coding-agent@${PI_VERSION}" --ignore-scripts \
 && pi --version

WORKDIR /workspace
ENTRYPOINT ["pi"]
