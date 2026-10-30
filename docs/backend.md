# Backend, registered agents and remote collection

Normal `traceward run` commands require the TraceWard backend. The CLI collects
supported gVisor and agent-hook evidence, samples workspace state and buffers
uploads locally. Correlation, evidence graphs and judge requests run on the
backend. PostgreSQL is authoritative for server data. This supersedes the old
local JSONL/SQLite live architecture; dated evaluation results remain historical.

## Start the service

From the checkout:

```sh
docker compose up -d --build
```

Open <http://localhost:8765>. Compose builds the backend and UI, starts
PostgreSQL 18, applies versioned schema setup and waits for readiness. The UI
proxies API calls and event-stream updates to the backend. PostgreSQL and the
backend have no published ports; neither receives the Docker socket or agent
workspaces. Database state lives in the `postgres-data` named volume.

The service is intentionally unauthenticated and single-workspace. The published
port binds to loopback by default. Use `TRACEWARD_BIND=0.0.0.0` only on a trusted
network or behind an existing access gateway. Configure `TRACEWARD_PUBLIC_HOST`
for a DNS hostname; set `TRACEWARD_PUBLIC_ORIGIN=https://your-host` when TLS is
terminated by an external reverse proxy. Browser requests remain same-origin.

Useful commands:

```sh
docker compose ps
docker compose logs -f backend
docker compose restart backend
docker compose down
```

Ordinary `down`/`up` preserves the volume. Do not use `down -v` unless you intend
to delete the database. The UI port is configurable with `TRACEWARD_PORT`.

## Configure the backend judge

Compose reads the checkout `.env`. Existing provider/model selection is retained:
`TRACEWARD_JUDGE_PROVIDER`, `TRACEWARD_JUDGE_MODEL`, `LMSTUDIO_API_KEY` and
`OPENROUTER_KEY`. Keys stay on the backend and never enter the observed guest.

For local LM Studio, set `TRACEWARD_BACKEND_JUDGE_URL` to a URL reachable from
the backend container. Its default is
`http://host.docker.internal:1234/v1/chat/completions`; Linux uses the supplied
host-gateway mapping. The model server must listen on an interface reachable
from Docker. OpenRouter uses its fixed provider endpoint instead.

The approved default model remains `qwen/qwen3.8-27b`; explicitly configured
providers and models take precedence. There is no model fallback or fabricated
score. Model failures remain visible and do not stop evidence capture.

Run the backend outside Compose with `pip install -e '.[server]'`, a
`DATABASE_URL`, and `traceward backend --host 127.0.0.1 --port 8000`.
`traceward dashboard` is an API-server compatibility alias; use Compose for the
separate UI. Direct frontend development can use the existing Vite proxy.

## Register an agent and launch

In **Agents**, choose **Create agent**, then supply the authorised goal and optionally a lowercase slug.
TraceWard generates an immutable UUID and a unique slug if omitted. Agent
editing/deletion is not exposed in this first version.

```sh
traceward run --traceward-url http://localhost:8765 \
  --agent-slug release-reviewer pi --print 'Inspect README.md'

traceward run --traceward-url http://localhost:8765 \
  --agent-id AGENT_UUID codex --sandbox workspace-write \
  -c sandbox_workspace_write.network_access=true exec 'Run the checks'
```

Pi remains a separately installed optional package. Install it with
`uv pip install --python .venv/bin/python --no-deps -e evaluation/pi`.

The URL precedence is the flag, then `TRACEWARD_URL`, then
`http://localhost:8765`. The registry is consulted before the agent launches.
An unknown agent or unreachable backend stops startup. Supply exactly one
selector. A registered agent's configured goal is snapshotted and overrides
both `--goal` and `--goal-file`; ignored files are not opened. Native agent
arguments are forwarded unchanged, and the registry goal controls observation
rather than rewriting the agent's prompt. Without a selector, existing goal
selection applies and the run stays **Unattributed**.

The agent UUID/slug are attached to run records, events, findings, assessments
and evaluation audit records. OCSF records use `unmapped.traceward` for these
extensions. Native session, turn and subagent IDs retain their own meaning.

Live-run `--judge-*` flags are rejected: configure the server instead. Pi actor
configuration such as `--pi-model` and `--pi-url` remains on the collector host.

## Collection, upload and analysis

The CLI preserves supported runtime handling, terminal forwarding and agent exit
status. Local owner-only run directories contain native sources and a durable
`upload.jsonl` spool. Uploads contain up to 500 records per batch with a roughly
1 MiB batch target. Requests acknowledge committed PostgreSQL transactions.
Sequence IDs make identical retries safe; conflicting submissions are rejected.
Only allowlisted evidence is uploaded, never arbitrary run-directory files,
credentials, CA private keys or agent homes.

Initial registration requires connectivity. During a later outage the agent
continues and uploads retry from the local spool. At exit the CLI makes a bounded
flush attempt and reports any pending data:

```sh
traceward sync RUN_UUID --traceward-url http://localhost:8765
```

Keep the local spool until upload succeeds. A successful agent exit does not
establish a successful upload or complete analysis. The UI distinguishes capture,
accepted/processed inputs and analysis. A missing collector heartbeat produces an
incomplete/disconnected state while preserving received evidence.

The backend uses ordered durable inputs and a per-run ownership lock, with up to
four active correlation owners and two concurrent judge requests. Additional
runs remain queued. On restart it reconstructs state from inputs using stable
event/finding IDs and cached evidence-packet decisions. No Redis is required.

After capture closes, the backend finishes pending and final assessments without
holding the CLI open. This supersedes the earlier live-exit rule that required a
manual replay for remaining assessments. Judge guards, coverage reporting and
the difference between internal assessments and current review findings remain.

Independent filesystem sampling and frozen validation still run on the collector
host. A remote backend never resolves those workspace paths against its own
filesystem. Native runtime/platform limitations remain unchanged; this migration
does not add arbitrary-container or universal agent instrumentation.

## API and storage

The registry supports creation/list/detail and agent-specific runs under
`/api/agents`. Run registration, ordered ingestion, heartbeats and capture
completion use `/api/runs`. Existing investigation reads, raw excerpts, evidence
citations, activity, operation chains and SSE updates remain available.

PostgreSQL stores registry goals, immutable run bindings, raw source bytes,
normalized JSONB events, graph observations/edges, assessment revisions, findings,
judge audit records and processing status. Raw source content is retained without
rewriting native records. Source evidence remains subject to the existing
redaction and content-capture settings; collection is not tamper-proof.

Back up and restore the database using standard PostgreSQL tools:

```sh
umask 077
docker compose exec -T postgres pg_dump -U traceward -Fc traceward > traceward.dump
# Restore into an empty database while the backend is stopped.
docker compose stop backend
docker compose exec -T postgres pg_restore -U traceward -d traceward < traceward.dump
docker compose start backend
```

Historical local runs are not imported automatically. The owner-requested fresh
transition removes old canonical run directories and rebuildable indexes; separate
dated validation reports remain historical. Subsequent ordinary deployments and
restarts never delete existing PostgreSQL runs.

The measured migration and recovery results are recorded in the
[2026-10-30 acceptance record](backend-validation-2026-10-30.md). Browser regression
fixtures can use `TRACEWARD_BROWSER_DATABASE_URL`; it must point to a disposable
database because fixture setup truncates its tables. Core integration tests use
the separate `TRACEWARD_TEST_DATABASE_URL` setting.

For a disposable test database, separate from the deployed service:

```sh
docker run --rm -d --name traceward-tests \
  -e POSTGRES_PASSWORD=test-local -p 127.0.0.1:55439:5432 postgres:18
# Wait until this reports accepting connections.
docker exec traceward-tests pg_isready -U postgres
TRACEWARD_TEST_DATABASE_URL=postgresql://postgres:test-local@127.0.0.1:55439/postgres \
  .venv/bin/python -m unittest discover -s tests -q
npm run build --prefix web
TRACEWARD_BROWSER_DATABASE_URL=postgresql://postgres:test-local@127.0.0.1:55439/postgres \
  npm run test:e2e --prefix web
docker stop traceward-tests
```

Run the core and browser suites sequentially: both reset their selected disposable
database. Set `TRACEWARD_TEST_ZSHRC` explicitly to opt into checks of installed
`tpi`/`tcodex` wrappers without launching either agent.
