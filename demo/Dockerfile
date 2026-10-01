FROM python:3.11-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends strace nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# Keep a real Codex CLI available for an operator-signed-in follow-on run.
# The default demo deliberately shadows it with the labelled simulator.
RUN npm install --prefix /opt/real-codex @openai/codex

COPY . /opt/traceward
RUN pip install --no-cache-dir -e /opt/traceward \
    && install -m 755 /opt/traceward/demo/agent_simulator.py /usr/local/bin/codex \
    && chmod 755 /opt/traceward/demo/entrypoint.sh /opt/traceward/demo/real_codex.sh

WORKDIR /opt/traceward/fixtures/disguised
ENV PYTHONUNBUFFERED=1 XDG_STATE_HOME=/traceward-state \
    TRACEWARD_LAYA_MODEL=demo-deterministic-evaluator
ENTRYPOINT ["/opt/traceward/demo/entrypoint.sh"]
