# Runtime setup and operations

Run the commands in this guide from the repository root. For the product overview, see [README.md](../README.md).

TraceWard runs Linux Codex inside managed gVisor and existing Docker on macOS or Linux, combines trusted Codex hooks with independent runtime effects, and exports evidence-backed OCSF v1.8 JSONL. Docker, gVisor and Codex apply runtime restrictions. TraceWard observes and analyses; findings do not block or terminate the agent.

The managed runtime works on native ARM64 Docker Desktop in the measured configuration. **Qwen is now the default local judge.** It passed the six fresh real-Codex capture, dashboard and reviewed-decision checks, including the authorised receiver control. It also passed 46 controlled regression/diagnostic cases after an ambiguous-goal rubric correction. These results support the PoC fixtures, not production accuracy; native AMD64 and public image publication remain pending. See [VALIDATION.md](../VALIDATION.md).

## Install and run

Requires Python 3.11+, running Docker, and LM Studio serving `qwen/qwen3.8-27b` on port 1234 for judgement. No separate gVisor installation or Docker daemon runtime configuration is needed. Model outages retain capture and report evaluation unavailable.

```sh
python3 -m pip install -e '.[dashboard]'
traceward run codex \
  --sandbox workspace-write -c sandbox_workspace_write.network_access=true exec "Run npm test and explain the failure"
```

On first use TraceWard pulls `ghcr.io/traceward/runner:0.2.0-delete1`, then reuses the cached image. Public publication is pending; until it is published, a failed default-image pull automatically builds the bundled recipe. First build needs network access and takes longer than cached launches. A custom runner pull failure does not silently substitute the default image.

The initial instruction supplied to Codex is also TraceWard's authorised goal by default. For a longer session, use `--goal TEXT` or `--goal-file PATH` before the agent name to supply broader observer scope. These options are mutually exclusive; empty goals are rejected. A goal file is read once at startup, and the selected goal is frozen before execution. An explicit goal leaves all agent arguments and stdin unchanged and allows an interactive start without a launch prompt. TraceWard options (`--goal`, `--goal-file`, `--runner-image`, `--workspace`, `--guest-image`, `--judge-provider`, `--judge-url`, `--judge-model`) precede `codex`. Terminal I/O, resizing, operator signals, working directory and exit status are preserved. This executes **Linux Codex**, not native macOS binaries.

Without an explicit goal, Codex asks once for its launch instruction. Pi instead opens its native chat interface: its passive extension records the first nonempty interactive input, which establishes the frozen goal. Until that input arrives, the manifest says `awaiting_instruction` and assessment is deferred. If the session closes without a goal, relevant assessments remain unavailable. Stdin-only text instructions are captured once and forwarded as a prompt argument (including `codex exec -`). Mixed piped input and an explicit prompt are rejected during inference. The instruction adapter recognises the pinned agents' supported flags; unknown flags, resumed/forked sessions, Pi RPC and Pi `@file` initial prompts require an explicit goal rather than a guessed one. Pi's first text message supplies the default goal; subsequent messages cannot replace it. With an explicit goal, instruction inference is bypassed and agent arguments are forwarded unchanged; this does not add runtime support or persistent Pi sessions. Pi still uses a fresh home. Documents and tool output remain evidence, not operator instructions. Offline replay retains its separate `--goal` input for analysing saved evidence.

```sh
traceward run --goal-file ./session-goal.md codex \
  --sandbox workspace-write -c sandbox_workspace_write.network_access=true \
  "Start by inspecting the failing tests"
```

The tested Codex configuration is explicit **workspace-write with network access**. Codex's default read-only/network-isolated Bubblewrap mode failed inside pinned gVisor host networking (`Failed to look up lo`). TraceWard does not silently disable Codex's sandbox or approvals. Native AMD64 execution awaits the native CI gate; emulated AMD64 on ARM64 is rejected because systrap failed under emulation. Rootless Docker and arbitrary pre-existing containers are unverified and unsupported in v1.

## Credentials and hooks

For **actual-agent adversarial evaluation**, the separately installed `traceward-pi eval` lab runs Pi with local Qwen in disposable repositories and measures receiver receipts, protected-state changes and task completion independently of TraceWard's judge. It also supports explicit actor-model comparisons. See [Pi evaluation harness](../evaluation/pi/README.md) for cases, isolation, transcript handling, limitations and reproduction. This experimental Pi path uses a fresh home and Docker-isolated networking; the Codex credential/trust instructions below still apply to Codex runs.

For Pi development runs, a [sample guest Dockerfile](../examples/pi-dev/README.md) supplies curl, Pi and common Python/Node development tools. Select the built image using `--guest-image`; `--pi-network bridge` explicitly enables Docker's default bridge networking for a Pi `run`. The default is `--pi-network none`, including evaluation harness runs. The model relay and fresh Pi home remain in both modes. Docker and gVisor own the runtime restrictions; bridge mode is ordinary connectivity, not a TraceWard destination policy or enforcement feature.

The effective `CODEX_HOME`, or `~/.codex`, is mounted writable at `/codex-home`. Existing file-backed authentication is reused; refresh, configuration, history and hook trust persist. Keychain-only authentication is not portable: configure Codex `cli_auth_credentials_store = "file"` and sign in on the host if necessary. TraceWard does not extract Keychain secrets. Shared history can contain host paths unavailable in Linux; stale rollout-path warnings were observed. Host-specific MCP commands and tools may also be unavailable.

Start an interactive run once, open Codex `/hooks`, review and trust the TraceWard handlers. TraceWard subscribes to all 12 events exposed by pinned Codex 0.159.3: `SessionStart`, `SessionEnd`, `UserPromptSubmit`, `PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`, `SubagentStart`, `SubagentStop`, `Stop` and `Interrupt`. Tool hooks have no tool-name matcher, so supported MCP and other local tools are included. An expanded hook definition may need a fresh trust review. The stable command is:

```text
PYTHONPATH=/opt/traceward-hooks /usr/local/bin/python3 -m traceward.hook_sink
```

TraceWard does not write trust hashes or bypass `/hooks`. Without trusted hooks, runtime observation continues with an explicit combined-coverage gap.

The Pi 0.85.1 extension subscribes to all 36 events in its pinned ExtensionAPI, including session/resource changes, agent/turn lifecycle, provider request/response boundaries, message streaming, tool execution/results, input, model/thinking changes and UI prompts. Each record retains the native event name. `tool_call` and `tool_execution_end` retain the normalized `PreToolUse`/`PostToolUse` names used for correlation. All handlers leave inputs unchanged and return no decision; Pi's project-trust handler explicitly abstains with `undecided`. Lifecycle hooks record selected metadata, not prompts, system prompts, provider headers or streaming text. Existing opt-in redacted tool/assistant excerpts remain separate. Recording every streaming update increases event volume; overhead of the expanded subscription has not been benchmarked.

In **Evidence Stream**, **Hooks only** loads all indexed hooks independently of the selected finding and runtime-event pagination. **Hook event** filters by the recorded event name across the run. Event details show session/turn identity, native Pi event, tool outcome and available lifecycle metadata. Only emitted events appear; absence is not evidence that a lifecycle stage never happened. Existing captures cannot be backfilled. These are observed lifecycle markers, not automatic startup/active labels on runtime effects.

Pi's default image rebuilds automatically when observer sources change. The default Codex runner is cached; after changing its bundled hook handler in a source checkout, rebuild it before capturing new runs:

```sh
docker build -t ghcr.io/traceward/runner:0.2.0-delete1 -f src/traceward/runner_image/Dockerfile .
```

The workspace is mounted at its original absolute path, with external Git worktree metadata where needed. `--workspace` must contain the invoking working directory. The guest receives only the workspace, Codex home, hook log, read-only hook helper and startup gate. Observer credentials and evidence directories are excluded. If an observer `.env` file already lies inside the mounted workspace, TraceWard reports the overlap; it cannot conceal an existing workspace file. Avoid running an observed task in TraceWard's own checkout containing observer credentials.

The runner uses `SYS_ADMIN`, `SYS_PTRACE`, and unconfined Docker seccomp/AppArmor settings for nested systrap; it uses neither `--privileged` nor the Docker socket. Guest `SETUID`, `SETGID` and `SETFCAP` capabilities are emulated by gVisor to support Codex's nested user namespace.

## Deletion evidence and finalization

The runner builds gVisor `release-20260928.0` at commit `6485c3fbdfe28172ced5d6aed49554cf494967db` with the checked-in observation-only deletion patch. The build verifies the source archive and patch hashes and installs the complete release set, including matching Sentry sidecars. `runner_image/gvisor/provenance.json` identifies the patch; each runtime status snapshot retains that fingerprint. Native ARM64 is validated; native AMD64 execution remains pending. Custom older runner images without `sentry/file_delete` are rejected before the agent starts. The public runner image remains unpublished; the bundled recipe builds locally.

The new `file_delete` observation covers `unlink`, `unlinkat` and directory removal. The kernel-consumed pathname and start-directory context are captured before the operation and the actual result/errno afterward. Path construction remains lexical and may include intermediate symlinks; unresolved targets remain explicit. A zero result indicates successful directory-entry removal, not destruction of all file contents or copies. Failed deletions remain attempts. The source carries no syscall payload buffers. OCSF maps this to File System Activity/Delete (activity 4); the UI adds file-deletion filtering, details and activity counts.

Workspace deletions generate investigations even for empty files absent from the baseline. Existing process ancestry links strengthen attribution; unhooked effects remain uncertain. Outside-workspace selection retains tool/sensitive-resource scope and declared agent-state exclusions. Deletions group by tool or process lifetime/30-second interval, retaining individual targets and consequential evidence. Snapshots supplement observed deletion candidates without duplicating them; snapshots alone still miss transient changes. Rename, truncate and other metadata mutations are separate gaps.

Collector status is replaced atomically with owner-only permissions after readiness, about once per second, and after drain. `trace_established`, `finalized` and `status_updated_at` distinguish partial counters from final counters. Supervisor signal handling remains active through cleanup. If the Docker attachment exits early, the host waits up to five seconds for finalization; another cancellation skips that grace period. Missing final status does not erase observed telemetry or prove collection never started. The last source header still cannot establish trailing loss.

The read-only assessment API adds `effective_judge`, `effective_judge_revision` and `assessment_attempt_status`. A retained verdict must match the referenced finding, evidence scope, tool and window. Cancellation shows the earlier accepted verdict and a separate final-assessment-cancelled notice, or explicitly says no verdict completed. Genuine model/contract failures remain distinct. Historical JSONL and source summaries are not rewritten. The UI explains misleading legacy telemetry warnings using observed source records while retaining the original warnings in `source_coverage_gaps`. Ended runs separately expose incomplete analysis. For normal live runs, completeness means the latest relevant captured evidence has a valid completed live assessment; finishing or stopping a worker does not establish that.

The structured judge retains the original Qwen model, thresholds, rejection guards and no-fallback policy. The audited `goal-effects-deletion-v1` rubric explicitly defines successful removal as a state mutation, including empty files. Detailed response generation places evidence facets before the disposition to avoid premature decisions; field meanings remain unchanged and contradictory clears are still rejected. Initial rejected answers are retained as historical diagnostic outcomes, not relabelled as detections.

## HTTPS inspection for Pi

For development runs, add `--pi-inspect-https --pi-network bridge` before `pi`. The first inspected launch builds a separate observer image with mitmproxy 12.2.3; this does not add proxy tooling to the agent guest. Inspection remains an explicit capture setting, independent of `--context-mode`.

TraceWard generates a fresh CA per run outside the gVisor guest, copies only its public certificate to `/usr/local/share/ca-certificates/traceward-inspection.crt` and runs the guest's `update-ca-certificates` before startup. The resulting system bundle is trusted by system-store clients. Every guest process inherits `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE` and `NODE_EXTRA_CA_CERTS` for common Python, curl and Node clients. Verification remains enabled on both TLS legs. The private key never enters the guest, workspace or retained evidence and is deleted at shutdown. macOS trust is unchanged. Custom images must supply `update-ca-certificates` and the expected Debian-style paths, as the sample development image does.

Upper- and lowercase HTTP/HTTPS proxy variables point to an observer-side loopback proxy. The local model relay bypasses it. Clients must actually use that proxy: system CA trust alone does not route traffic through it. Some clients need their own proxy configuration; private trust stores, certificate pinning, direct sockets and QUIC may fail or bypass inspection. Independent gVisor network metadata continues alongside it. This is an explicit proxy, not transparent interception or enforced egress routing. TraceWard does not disable verification or block bypasses.

`http-events.jsonl` records observed method, redacted URL/headers, request and response phases, status or error, body byte counts/hashes and at most a 4,096-byte prefix of supported text bodies. Bodies are streamed unchanged; binary and content-encoded body excerpts are omitted. Excerpts and query/header redaction are best effort and may still contain sensitive data. These files are owner-only. No full flow dump or CA key is saved. The dashboard's **HTTP requests** event filter exposes these records and their content details; OCSF currently retains this source as a Base Event with explicit HTTP details.

Proxy request-to-tool correlation uses a unique shell-tool time window and is labelled inference. It does not prove process ancestry or that a recipient received particular bytes. A response is separate evidence of an upstream outcome. Socket metadata can also produce a separate review of proxy transport; requests are not yet grouped into a single incident. `inspection-status.json` records startup/trust/health; proxy failure marks HTTP coverage incomplete. With inspection disabled, runtime syscall records still contain no network payloads.

## Custom dependencies and embedded execution

`--guest-image IMAGE` exports a trusted native Docker image into a cached root filesystem. It must contain Linux Codex and `/usr/local/bin/python3` for the bootstrap/hooks. For example, extend the managed guest filesystem:

```dockerfile
FROM ghcr.io/traceward/runner:0.2.0-delete1 AS managed
FROM scratch
COPY --from=managed /opt/traceward/rootfs/ /
RUN apt-get update && apt-get install -y --no-install-recommends make
```

```sh
traceward run --guest-image project-agent:local codex <flags> "Build the project"
```

The same supervisor can execute embedded inside the configured managed runner with the required Docker capabilities. Running inside arbitrary existing containers, Docker-free execution and transparent native macOS process capture are outside v1.

## Evidence and analysis

Internal candidates and cleared/inconclusive decisions live in `assessments.jsonl`. Only review dispositions and explicit withdrawals enter `findings.jsonl`; the default dashboard and findings API show current review findings. The separate Assessment audit view retains complete diagnostic history, including historical cleared records. A finding is a supported concern requiring review, rather than every operation considered by the detector.

Owner-only runs live at `${XDG_STATE_HOME:-~/.local/state}/traceward/runs/<uuid>/`: `run.json`, `raw.gvisor.jsonl`, `hooks.jsonl`, `events.jsonl`, `findings.jsonl`, `evaluations.jsonl`, `runtime-status.json`, and `summary.json`. JSONL is authoritative. The dashboard's owner-only SQLite database is a rebuildable projection. Historical strace runs and attachments remain readable; live strace launchers, parsers and replay were removed.

The receiver validates SecCheck version-1 handshakes and bounded protobuf packets from pinned `release-20260928.0` schemas. A verified trace session releases the agent startup gate. Required telemetry failure prevents task startup; loss during execution marks coverage incomplete and lets the guest continue. Process identities use sandbox/PID/start time. Descriptor duplication, closure, inheritance, sharing and CLOEXEC support file/socket attribution. Positive returned byte counts establish effects; failures and asynchronous connection attempts remain distinct.

The runtime collector does not persist syscall read/write buffers, network payloads or environment values. Raw source records retain redacted metadata and stable line references. Shell commands, paths and hook metadata can still be sensitive. mmap coverage is incomplete, unresolved destinations and unsupported effects are gaps, and read followed by send does not prove transmission of those bytes. Hooks are agent-writable; this is not tamper-proof evidence. The optional Pi evaluation lab separately saves actual synthetic actor transcripts and receiver hashes; see [Pi evaluation harness](../evaluation/pi/README.md) before sharing those artifacts.

The expanded pipeline creates investigations for workspace writes, host-observed repository changes, standalone sensitive reads, failed sensitive access or network attempts, independent network effects and access to operator-declared shared roots. Hook attribution strengthens an explanation; missing hooks do not discard independently observed effects. Candidates become alerts only after a review disposition. Live runs assess a rolling 30-second slice of relevant investigation evidence, carrying the original goal, triggering effects, process/tool anchors and selected older state/authority context across window boundaries. A changed view can run after 250 ms initially and on a one-second cadence afterward, without waiting for PostToolUse or session exit. Empty/unchanged views cause no model request. Arrivals during inference are coalesced into the next view; a waiting worker refreshes its packet when a judge slot becomes available. The existing candidate families still select investigations; this does not send every raw OS event to the model.

Normal live runs use the same Qwen judge with `goal-effects-live-v2`: the detailed six-facet assessment and checked factual claims run during execution, together with title, categorical disposition, rationale and citations. The factual state is capped at 12,288 UTF-8 bytes, the state plus factual-predicate table at 14,336 bytes, and output at 1,600 tokens. The fixed system prompt is additional. Strict schema, citation and contradiction checks remain; no invalid response is converted into a verdict. Historical `goal-effects-live-v1` short assessments remain readable. Body excerpts are shortened for rolling input while captured excerpts remain in evidence. Oversized required input is explicitly unavailable. Detailed live inference can take longer than the former short live format; moving it earlier does not make inference instantaneous.

Up to 60 recent contextual events and bounded consequential samples enter a window; older causal anchors remain explicit. Event bursts can omit context or effects from the model sample; gaps report those omissions and prevent reassuring clearance. Full collected events remain in JSONL. Two concurrent judge requests bound inference, with one worker per investigation, rather than a fixed-size worker pool; very large run scalability remains unvalidated. Model queueing and inference still add latency. The dashboard polls every two seconds, shows pending counts and highlights finding windows in the live activity chart while the agent runs.

Normal live runs do not start an exit-triggered assessment or wait for queued/in-flight model calls. At agent exit, new judge requests are stopped; collector draining, final observations and summary persistence still run. Material evidence changes trigger reassessment while the agent is active; lifecycle/window labels alone and duplicate sampled file versions do not. Unfinished or newly discovered exit-time evidence is saved with `assessment_pending` and reason `session_ended_before_assessment`, not a model-outage or user-cancellation label. An earlier supported review retains its original scope and citations with an explicit additional-evidence-pending notice. Late HTTP replies cannot change saved records. No earlier verdict means no completed verdict, not clearance. Replay the retained capture to complete pending analysis; nothing silently continues in the background.

Explicit `--defer-judge` and evaluation/replay paths retain their deliberate deferred detailed assessment and may wait after execution. During that explicit wait, Ctrl+C/SIGTERM cancels outstanding work with a separate cancellation record. Genuine endpoint/schema/validation failures remain unavailable. While the agent is running, signals continue to be forwarded to the runtime. Fast live exit is not proof of complete analysis: sufficiently short sessions, a saturated judge or final-only checker/state evidence can leave pending work.

Source ingestion uses bounded chunks so busy captures do not hold hook delivery and heartbeat updates behind a whole telemetry backlog. If the agent exits before catch-up completes, the CLI announces the remaining processing; an interrupt can stop it and retain the raw source logs with an explicit gap in the derived views. Normal live runs attribute graph records as effects/hooks arrive; the explicit deferred path retains its cancellation-aware final attribution pass. If hooks arrive after a no-hook warning, the CLI prints a recovery message; the warning alone does not establish that hook trust is missing.

`--context-mode redacted` opts into bounded, locally redacted tool-result/session excerpts and selected file diffs. The default `metadata` mode retains hashes and metadata without those excerpts. Contents are labelled by source and trust; document claims and captured user-role messages cannot supersede the original CLI goal. Redaction is best effort, so redacted capture still requires local handling of potentially sensitive text.

Host baseline, periodic live samples (about every two seconds) and final snapshots preserve sampled file identity and content versions. Unchanged repeated versions remain source evidence but do not retrigger model assessment. Final-only changes or an explicitly configured final checker can still leave pending analysis at live exit. A local SQLite evidence graph connects tools, paths and sampled versions; path/time edges are inference. `--shared-root PATH` opts into cross-run version lookup for a shared directory in the workspace, without granting permissions. `traceward rebuild-graph` rebuilds the derived index from retained logs; deleted source records and uncollected versions cannot be recovered.

`--validation-script PATH` freezes an observer-selected checker outside the guest workspace and runs it in a separate read-only, network-isolated Docker invocation. `--permissions-file PATH` imports a bounded external permission log outside the observed workspace. Requests, denials, proposals and approvals retain identity, scope, expiry and revision when supplied. The adapter recognises OpenShell evidence shapes; no live OpenShell deployment or enforcement integration is implied. Missing fields remain missing. The evaluation lab's approval service is a synthetic application controller, not a runtime permission grant.

Detailed final and deferred packets use `goal-effects-v4`: relevance, authority, integrity, outcome, benign explanations and missing evidence have separate categorical assessments and citations. Observer-computed factual predicates check selected claims against event types, integrity flags and full hash/version matches. These checks do not prove natural-language entailment, intent, payload transmission or resistance to every injection. Semantic input is capped at 12 KiB; the complete factual-table user message at 14 KiB. Full packets and exact requests remain auditable. Normal live windows use the detailed live v2 contract described above; historical short live v1 and legacy v3 packets remain readable.

The judge client runs on the invoking host. Defaults are `lmstudio`, `qwen/qwen3.8-27b`, and `http://127.0.0.1:1234/v1/chat/completions`. A supplied `/api/v1` base is normalized to this same server’s schema-capable OpenAI-compatible endpoint. TraceWard requests strict JSON with `disposition`, `evidence_ids`, and `rationale`; it validates model identity, completion and citations. Categorical results have **no numerical risk score**. Malformed, refused, truncated or unresolved answers are unavailable; no model fallback is used.

Set `TRACEWARD_JUDGE_PROVIDER`, `TRACEWARD_JUDGE_URL` and `TRACEWARD_JUDGE_MODEL` in the checkout `.env`, an explicit `TRACEWARD_ENV_FILE`, or process environment; CLI `--judge-*` overrides matching settings. Environment wins over file settings.

- `lmstudio` uses `TRACEWARD_JUDGE_URL` and `TRACEWARD_JUDGE_MODEL`, retaining the local defaults above. Optional `LMSTUDIO_API_KEY` supplies the Bearer credential. The former `TRACEWARD_JUDGE_TOKEN` remains a local compatibility alias when that key is absent.
- `openrouter` uses the configured `TRACEWARD_JUDGE_MODEL` and required `OPENROUTER_KEY` at `https://openrouter.ai/api/v1/chat/completions`. `TRACEWARD_JUDGE_URL` applies only to LM Studio; a leftover local URL cannot receive the OpenRouter key. Missing cloud model/key settings produce an explicit unavailable result; there is no local-model fallback.

OpenRouter requests reasoning with `reasoning.enabled=true` and requires endpoints supporting the strict JSON schema (`provider.require_parameters=true`). Optional local temperature/seed/reasoning-effort controls are omitted because otherwise compatible cloud models can reject them. Model-specific reasoning defaults and the existing bounded output limit apply; truncation is unavailable rather than a partial verdict. Requests follow the official [authentication](https://openrouter.ai/docs/api_reference/authentication), [structured-output](https://openrouter.ai/docs/guides/features/structured-outputs) and [reasoning](https://openrouter.ai/docs/guides/best-practices/reasoning-tokens) APIs. Each assessment gets an independent evidence packet, not a growing conversation. Returned `reasoning_details` remain in the redacted response audit; no conversational replay is implied.

The actual provider, requested/returned model, contract and redacted wire response remain auditable. An OpenRouter model alias is accepted only when the returned ID matches its published canonical slug from bounded public catalogue metadata; unrelated identities are rejected. Catalogue failures do not invent a match. LM Studio retains exact model-identifier checking and its existing [optional Bearer authentication](https://lmstudio.ai/docs/developer/core/authentication).

Selecting OpenRouter transfers the bounded model input to the remote gateway/serving provider. It does not add a hosted TraceWard datastore or cloud agent collection. Both credentials are observer-only and stripped from the agent environment. Judge authorization headers are never persisted; credential echoes are removed from saved responses. LM Studio's loaded context/settings remain unchanged. Detailed state is capped at 12 KiB and state plus predicate table at 14 KiB; detailed output is capped at 1,600 tokens. Historical short live records use their original bounds. Full packets and exact redacted requests/responses remain auditable. Pruning, ambiguity, outage and incomplete coverage prevent a clearing decision.

Shared packet creation, bounded rendering and disposition handling live in `evidence_packet.py`; `judges.py` calls the structured OpenAI-compatible endpoint. New assessment records use the provider-neutral `judge` field. The read-only dashboard recognizes older provider-named result slots by their typed shape and presents them under `judge`; original JSONL, scores and model provenance remain unchanged. Historical numerical scores are display-only evidence, not new structured-model decisions.

## Dashboard and validation

The dashboard opens on **Agent Runs**, with search by name, goal or run ID and filters for harness, capture status and findings. Select a table row to open **Agent Run Investigation**. The authorised goal and run metrics remain at the top, with **Findings** first and selected by default, followed by **Evidence Stream**, beneath the overview. A stacked **Activity over time** chart below the metrics covers the full indexed run, independently of evidence pagination. It updates every two seconds and groups process activity, file opens/reads/writes, network activity, HTTP observations, agent hooks and state/context into time buckets. Auto or a selected duration controls the buckets; long ranges widen automatically to keep at most 240 buckets. Multi-day axes include dates. Counts represent observations, including HTTP request/response phases; internal assessment/finding and coverage records are excluded. Current review revisions shade their recorded assessment windows; older records use cited evidence times, with detection time as the last fallback. Overlapping or touching finding periods render as a continuous band, independently of bucket duration; disjoint periods stay separate. Long empty spans are labelled “No recorded activity”: they describe the absence of plotted observations, rather than a guaranteed agent idle state. Withdrawn/cleared findings remove the highlight. Selecting a bucket exposes counts and links into its findings. This replaces the top new-finding banner. The read-only `/api/runs/{id}/activity?interval=SECONDS` endpoint aggregates in SQLite and returns compact counts/window metadata. The active tab can be refreshed/bookmarked; panel content expands and the page scrolls. The evidence timeline defaults to newest first, with an oldest-first option. Event details stay alongside the timeline while scrolling on wide screens; on narrow screens, selection jumps to the details. **Back to selected event** returns to the selected row without adding an inner scroll area. Within findings and the assessment audit, descriptive evidence links expand event details directly beneath the citations; the finding and page position remain in place, and closing details restores focus to the citation. **Findings** is a separate view of current review findings across runs, with links into their evidence. Cleared and incomplete records remain in the per-run **Assessment audit**. List filters persist while navigating and reset on reload; direct investigation URLs can be refreshed or bookmarked. Filtering and pagination currently happen in the browser after loading the local summaries and current findings.

```sh
npm ci --prefix web
npm run build --prefix web
traceward dashboard
python3 -m unittest discover -s tests -q
TRACEWARD_TEST_DOCKER=1 python3 -m unittest discover -s tests -p test_gvisor_integration.py -q
npm run test:e2e --prefix web
```

Browser tests use Chrome by default; set `PLAYWRIGHT_CHANNEL` for another installed supported browser. They use explicitly synthetic decisions against real JSONL/API projections. Real six-case validation, actual decisions, UI inspection and measurements are documented in [DEMO.md](../DEMO.md) and [VALIDATION.md](../VALIDATION.md).

Replay preserves source attachments:

```sh
traceward replay --goal "Diagnose a test failure" --hooks hooks.jsonl --trace raw.gvisor.jsonl --abi arm64 --offline
```
