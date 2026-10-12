# Opt-in lab image. Reuses the measured gVisor base and its Linux guest.
FROM ghcr.io/traceward/runner:0.2.0 AS base
FROM scratch AS guest
COPY --from=base /opt/traceward/rootfs/ /
RUN npm install --global @earendil-works/pi-coding-agent@0.85.1 --ignore-scripts \
 && pi --version
FROM base
COPY --from=guest / /opt/traceward/rootfs/
COPY src/traceward /opt/traceward/src/traceward

COPY evaluation/pi/traceward_pi /opt/traceward/src/traceward_pi
