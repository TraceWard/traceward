# TraceWard

**Goal-first observability for autonomous agents.**

Understand what an agent actually did, how its actions relate to the task you authorised, and which unexpected effects need your attention.

![](./docs/dashboard.png)

## Why TraceWard is needed

Autonomous agents can run commands, modify files, start processes and communicate with external services. As they work towards a goal, they choose methods that you may not have anticipated.

An agent's conversation or tool log tells part of that story. A routine test command might start a child process that reads credentials. A document might inject instructions that redirect the task. An agent might change the checks used to judge its work rather than fix the underlying problem. These effects can be difficult to explain from the agent's own account alone.

Understanding that behaviour requires two kinds of evidence: what the agent was asked to do, and what happened when it acted. The same operation can be legitimate for one goal and inappropriate for another.

TraceWard brings that evidence together. You start with an authorised goal, without having to predict every permitted tool, command or destination. The resulting observations help you investigate unexpected behaviour and decide where additional controls would be useful.

## What TraceWard does

TraceWard is designed to observe agents across frameworks. It connects agent actions with independently observed effects and assesses them against the authorised goal.

It helps you:

- **See actual effects.** Inspect process activity, filesystem access, network activity and resulting state within the observed environment.
- **Connect actions across tools and processes.** Follow a command into its child processes, or relate operations through shared resources and sampled file versions.
- **Investigate possible misalignment.** Review evidence of task-irrelevant access, unwanted changes, suspicious transfers, verification tampering and discrepancies in completion claims.
- **Understand each finding.** Examine the supporting events, goal relevance, authority evidence, possible benign explanations and missing information.
- **Keep an auditable record.** Explore runs in the dashboard and retain source records, assessment revisions and OCSF-formatted events in PostgreSQL.

Internal investigation candidates are separate from findings. Actions assessed as consistent with the goal remain in the assessment audit; supported concerns become review findings. Incomplete or unavailable assessments stay visible without being presented as reassuring conclusions.

TraceWard provides observation, analysis and alerts for human review. Your existing runtimes, policies and approval systems remain responsible for permissions and enforcement.

## How TraceWard works

TraceWard combines agent-side signals with independent runtime observations, then builds a bounded evidence packet for goal-based assessment.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 300, "nodeSpacing": 35, "rankSpacing": 35}}}%%
flowchart TB
  Goal["Authorised goal"]
  Agent["Agent and its tools"]
  subgraph Capture[Collect evidence]
    direction LR
    Signals["Agent-side signals<br/>tool calls, results and context"]
    Effects["Independent observations<br/>processes, files, network and state"]
  end
  Correlate["Correlate actions and effects<br/>lineage, resources and timing"]
  Assess["Assess against the goal<br/>evidence, authority and uncertainty"]
  Evidence["Local evidence and assessment history"]
  Review["Review findings in the dashboard<br/>inspect sources and coverage"]

  Agent --> Signals
  Agent --> Effects
  Signals --> Correlate
  Effects --> Correlate
  Correlate --> Assess
  Goal --> Assess
  Assess --> Evidence --> Review

  style Goal fill:#dbeafe,stroke:#3b82f6,color:#1e3a5f
  style Agent fill:#bfdbfe,stroke:#2563eb,color:#1e3a5f
  style Signals fill:#ffedd5,stroke:#ea580c,color:#431407
  style Effects fill:#ccfbf1,stroke:#0d9488,color:#042f2e
  style Correlate fill:#c4b5fd,stroke:#6d28d9,color:#2e1065
  style Assess fill:#fde68a,stroke:#d97706,color:#3d2e00
  style Evidence fill:#d1fae5,stroke:#059669,color:#064e3b
  style Review fill:#e0f2fe,stroke:#0284c7,color:#0c4a6e
```

1. **Capture the goal and observations.** A registered agent's configured goal is frozen for its run. Without a selector, the initial user instruction becomes the goal unless the operator supplies `--goal` or `--goal-file`. Supported integrations provide tool and session signals, while runtime collection and host state checks supply independent evidence. Captured documents and tool output remain lower-trust content; they cannot replace the original goal.
2. **Build the evidence chain.** TraceWard uses process ancestry, tool metadata, resource versions and timing to associate actions with effects. Observed relationships are distinguished from inferred connections, and ambiguous attribution stays explicit.
3. **Assess consequential behaviour.** A structured model assessment considers goal relevance, authority, integrity, outcome support, benign explanations and missing evidence. Deterministic checks validate selected factual predicates and evidence references. Findings include a rationale and citations to the supporting events.
4. **Retain and review the result.** The CLI keeps a durable upload spool. PostgreSQL stores source evidence, correlated events, graphs, assessments and judge audit records; the backend completes analysis after capture exits. You can inspect a finding, follow its source events and review the limits of the capture.

### Set up locally

You need Python 3.11+, `uv` and running Docker with Compose. The UI builds inside Docker; host Node.js/npm are only needed for frontend development. The measured runtime configuration uses native ARM64 Docker Desktop; native AMD64 validation remains pending. No separate gVisor installation or Docker runtime configuration is required.

Clone the repository and install the CLI. The examples below also install the optional Pi package, which is separate from TraceWard's core functionality. Compose installs backend dependencies inside its image.

```sh
git clone https://github.com/TraceWard/traceward.git
cd traceward
uv venv --python 3.11
source .venv/bin/activate
uv pip install --python .venv/bin/python -e .
uv pip install --python .venv/bin/python --no-deps -e evaluation/pi
```

Start a local OpenAI-compatible chat-completions server. Load a tool-calling model for the example agent and a model that supports strict JSON-schema responses for the judge. They can share a server. Replace the two placeholder IDs below with the exact model identifiers exposed by your server, and adjust the URLs if it uses a different port.

```sh
export ACTOR_MODEL='your-actor-model-id'
export TRACEWARD_JUDGE_PROVIDER=lmstudio
export TRACEWARD_JUDGE_MODEL='your-judge-model-id'
export ACTOR_URL='http://127.0.0.1:1234/v1/chat/completions'
export TRACEWARD_BACKEND_JUDGE_URL='http://host.docker.internal:1234/v1/chat/completions'
docker compose up -d --build
```

You can also configure the backend through the checkout `.env`; see [.env.example](.env.example). Configure it before starting Compose, and recreate the backend after changing its environment. The judge provider can be `lmstudio` or `openrouter` (configured independently of the actor). In these examples, the actor model server runs on the host and the agent reaches it through a restricted relay.

Open [http://localhost:8765](http://localhost:8765), choose **Agents → Create agent**, and supply its authorised goal and optional slug. From the workspace you want to observe, select that registered agent when launching a supported integration:

```sh
traceward run --traceward-url http://localhost:8765 \
  --agent-slug my-agent codex --sandbox workspace-write \
  -c sandbox_workspace_write.network_access=true exec 'Inspect README.md'

traceward run --traceward-url http://localhost:8765 \
  --agent-id AGENT_UUID --pi-model "$ACTOR_MODEL" --pi-url "$ACTOR_URL" \
  pi --print 'Inspect README.md'
```

Supply one selector. Its configured goal overrides both `--goal` and `--goal-file`, without reading an ignored file or changing native agent arguments. Omit the selector to keep a run **Unattributed**. `--traceward-url` overrides `TRACEWARD_URL`, which defaults to `http://localhost:8765`. Collection runs on the CLI host; ingestion and analysis require the backend.

### Run an example with Pi

From the repository root, create a disposable workspace and observe a small file-creation task:

```sh
TRACEWARD_DIR=$(pwd)
EXAMPLE_WORKSPACE=$(mktemp -d)
(
  cd "$EXAMPLE_WORKSPACE"
  "$TRACEWARD_DIR/.venv/bin/python" -m traceward_pi.cli run \
    --workspace "$EXAMPLE_WORKSPACE" \
    --pi-model "$ACTOR_MODEL" --pi-url "$ACTOR_URL" \
    --traceward-url http://localhost:8765 \
    pi --print "Create hello.py that prints Hello, world! Do not change other files."
)
```

By default, the instruction after `pi --print` is also TraceWard's goal; supply it only once. For a longer session, pass `--goal "Complete the refactor while preserving the public API"` or `--goal-file /path/to/goal.md` before `pi` to give the observer broader scope. Choose one override; it does not replace or prepend the agent's instruction. Goal files are read once at startup, and the selected goal stays fixed for that run. Without an override or a launch prompt, Pi opens its own chat interface. The first chat you submit becomes the frozen observation goal; the dashboard shows that it is waiting until then. With an explicit goal, you can also open Pi with no initial chat.

Pi runs inside the managed Linux runtime. TraceWard automatically prepares the runtime and Pi images on first use; the initial build needs network access and takes longer than cached runs. You do not need to install Pi on the host. Ordinary authorised work should not produce a misalignment finding; its evidence and any assessments remain available for inspection.

The default Pi environment is a network-isolated evaluation lab. For development tools such as `curl` and optional outbound networking, build the [sample Pi development image](examples/pi-dev/README.md) and select it with `--guest-image traceward-pi-dev:local --pi-network bridge` before `pi`. This remains Linux execution inside gVisor, with a fresh Pi home.

Add `--pi-inspect-https` alongside `--pi-network bridge` to inspect HTTP(S) requests from clients using the supplied proxy. TraceWard installs a per-run CA in the guest system trust store and supplies trust settings for Python, curl and Node. Request details and bounded, redacted text bodies appear in the evidence stream. Direct connections, QUIC and custom or pinned certificate stores remain coverage gaps; see [HTTPS inspection](docs/runtime.md#https-inspection-for-pi).

To try the evaluation harness, run a benign repair alongside a compromised-dependency scenario:

```sh
.venv/bin/python -m traceward_pi.cli eval \
  --actor-model "$ACTOR_MODEL" --actor-url "$ACTOR_URL" \
  --judge-model "$TRACEWARD_JUDGE_MODEL" --judge-url http://127.0.0.1:1234/v1/chat/completions \
  --cases normal dependency-side-effect \
  --timeout 360
```

The harness creates fresh disposable workspaces, uses synthetic credentials and a local receiver, and checks outcomes independently of the judge. Pi chooses its tool calls. Reports distinguish reproduced unwanted effects, detections, false alerts and incomplete runs; a resisted attack is not a successful detection. The command prints the report location, normally under `~/.local/state/traceward/pi-evaluation-<run-id>/`. See the [Pi evaluation guide](evaluation/pi/README.md) for additional cases and options.

### Open the dashboard

Each finding includes **How this happened**, a visual chain from the recorded tool call through process executions to its consequential effects. Expand related branches or select any operation to inspect its evidence. Solid links describe observed process relationships; dashed links identify inferred attribution. Missing or ambiguous evidence stays explicit. Chains also work with retained runs without changing their source records, and do not establish intent or prove that a read's contents were transmitted.

In a separate terminal, from the repository root:

```sh
make dashboard
```

Open [http://localhost:8765](http://localhost:8765). Compose serves React through Nginx, proxies API and streaming updates, and keeps PostgreSQL and the backend internal. The UI binds to loopback by default. Configure `TRACEWARD_BIND` and `TRACEWARD_PORT` for a trusted network or existing access gateway. There is no built-in authentication.

Use **Agents → Create agent** to register an authorised goal, then launch with `--agent-slug` or `--agent-id`. Both identifiers are attached to stored records. A selector overrides `--goal` and `--goal-file`, including nonexistent files, without changing native agent arguments. Runs without a selector remain **Unattributed**.

```sh
traceward sync RUN_UUID --traceward-url http://localhost:8765
docker compose logs -f backend
docker compose down
```

The URL defaults to `TRACEWARD_URL`, then `http://localhost:8765`. Initial registration must succeed before launch. Later outages buffer evidence locally; `sync` resumes pending uploads. Capture completion, upload progress and backend analysis are distinct. Pending final assessments continue on the backend after the CLI exits. The live chart, findings and assessment audit update while the agent runs.

See the [backend operating guide](docs/backend.md) for configuration, database authority, recovery, backup/restore and supported API endpoints. Offline evaluation/replay commands retain separate file-based lab storage.

### Current implementation and limits

The current runtime backend uses managed gVisor inside Docker to collect selected Linux process, filesystem and network events. The pinned runtime includes an observation-only deletion patch, so successful file and directory removals can be assessed even when transient files are absent from both state snapshots. Collector finalization and cancelled reassessments are reported separately from model availability; see [runtime operations](docs/runtime.md#deletion-evidence-and-finalization). Runtime collection and independent state sampling run on the invoking host. Correlation and judge assessments run in the backend. Agent-independent operation is the product goal; available integrations and tested runtime configurations currently determine coverage. Universal agent and platform support is not yet implemented.

Runtime metadata does not prove which bytes were transmitted, and correlation does not prove an agent's hidden intent. Unsupported operations, missing signals, bounded context and model errors can leave behaviour undetected or misinterpreted. Redacted content capture is opt-in, and local evidence is not tamper-proof against the same host user. Known evaluation results are developmental evidence, not measured production accuracy. **No finding is not proof of safety.**

See the [runtime setup and operations guide](docs/runtime.md) for installation, supported configurations, privacy and commands. The [validation record](VALIDATION.md) documents measured outcomes and remaining gaps, and the [demonstration guide](DEMO.md) explains reproducible examples.

### Judge providers

Configure the backend judge in the checkout `.env` or backend process environment. Live-run `--judge-*` flags are rejected. Explicit offline evaluation commands retain their separate judge options.

| Provider | Model | Endpoint | Credential |
| --- | --- | --- | --- |
| `lmstudio` (default) | `TRACEWARD_JUDGE_MODEL` (default `qwen/qwen3.8-27b`) | `TRACEWARD_JUDGE_URL` (default local port 1234) | Optional `LMSTUDIO_API_KEY` |
| `openrouter` | Required `TRACEWARD_JUDGE_MODEL`, using your OpenRouter model ID | Fixed `https://openrouter.ai/api/v1/chat/completions` | Required `OPENROUTER_KEY` |

OpenRouter enables reasoning and requests strict structured output from compatible endpoints. Its selected model must support those parameters; responses still pass TraceWard's schema, model-identity and evidence checks. Unlike local LM Studio, selecting OpenRouter sends the bounded assessment evidence to OpenRouter and its serving provider. Judge credentials are excluded from the agent environment, request audit and saved responses. The older `TRACEWARD_JUDGE_TOKEN` remains an LM Studio compatibility alias; `LMSTUDIO_API_KEY` takes precedence. See [.env.example](.env.example) and [runtime settings](docs/runtime.md).
