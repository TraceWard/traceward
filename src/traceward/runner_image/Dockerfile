# syntax=docker/dockerfile:1
FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d AS gvisor-build
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git patch build-essential crossbuild-essential-amd64 crossbuild-essential-arm64 clang libbpf-dev libelf-dev libssl-dev libnuma-dev pkg-config unzip zip && rm -rf /var/lib/apt/lists/*
COPY src/traceward/runner_image/gvisor /recipe
RUN --mount=type=cache,target=/root/.cache/bazel python3 /recipe/build.py
FROM node:22.20.0-bookworm-slim@sha256:b21fe589dfbe5cc39365d0544b9be3f1f33f55f3c86c87a76ff65a02f8f5848e AS node
FROM python:3.11.14-slim-bookworm@sha256:65a93d69fa75478d554f4ad27c85c1e69fa184956261b4301ebaf6dbb0a3543d AS guest
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && apt-get update && apt-get install -y --no-install-recommends git=1:2.39.5-0+deb12u3 bash=5.2.15-2+b13 ca-certificates=20250419~deb12u1 \
 && rm -rf /var/lib/apt/lists/* \
 && npm install --global @openai/codex@0.159.3
FROM guest AS runner
ARG TARGETARCH
COPY --from=gvisor-build /out/bin/ /usr/local/bin/
COPY --from=gvisor-build /out/gvisor-provenance.json /opt/traceward/gvisor-provenance.json
COPY --from=guest / /opt/traceward/rootfs/
COPY src/traceward /opt/traceward/src/traceward
RUN pip install --no-cache-dir protobuf==6.33.5 \
 && python3 -c 'import json,subprocess,pathlib; p=pathlib.Path("/opt/traceward/versions.json"); p.write_text(json.dumps({"gvisor": "release-20260928.0", "codex": subprocess.check_output(["codex","--version"],text=True).strip(), "node": subprocess.check_output(["node","--version"],text=True).strip(), "python": subprocess.check_output(["python3","--version"],text=True).strip(), "git": subprocess.check_output(["git","--version"],text=True).strip(), "bash": subprocess.check_output(["bash","--version"],text=True).splitlines()[0]}))'
ENV PYTHONPATH=/opt/traceward/src TRACEWARD_MANAGED_RUNNER=1
ENTRYPOINT ["/usr/local/bin/python3", "-m", "traceward.runner"]
