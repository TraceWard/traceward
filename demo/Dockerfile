# Optional simulator demonstration, using exactly the managed runtime.
# This image deliberately replaces guest Codex with a labelled stand-in.
FROM ghcr.io/traceward/runner:0.2.0-delete1
COPY . /opt/traceward/project
RUN pip install --no-cache-dir -e /opt/traceward/project \
 && rm /opt/traceward/rootfs/usr/local/bin/codex \
 && install -m 755 /opt/traceward/project/demo/agent_simulator.py /opt/traceward/rootfs/usr/local/bin/codex \
 && chmod 755 /opt/traceward/project/demo/entrypoint.sh
WORKDIR /opt/traceward/project/fixtures/disguised
ENV XDG_STATE_HOME=/traceward-state PYTHONUNBUFFERED=1
ENTRYPOINT ["/opt/traceward/project/demo/entrypoint.sh"]
