# TraceWard

TraceWard runs Linux Codex inside managed gVisor and existing Docker on macOS or Linux, combines trusted Codex hooks with independent runtime effects, and exports evidence-backed OCSF v1.8 JSONL. Docker, gVisor and Codex apply runtime restrictions. TraceWard observes and analyses; findings do not block or terminate the agent.

The managed runtime works on native ARM64 Docker Desktop in the measured configuration. **Qwen is now the default local judge.** It passed the six fresh real-Codex capture, dashboard and reviewed-decision checks, including the authorised receiver that Laya incorrectly flagged. It also passed 46 controlled regression/diagnostic cases after an ambiguous-goal rubric correction. These results support the PoC fixtures, not production accuracy; native AMD64 and public image publication remain pending. See [VALIDATION.md](VALIDATION.md).

## Install and run

Requires Python 3.11+, running Docker, and LM Studio serving `qwen/qwen3.8-27b` on port 1234 for judgement. No separate gVisor installation or Docker daemon runtime configuration is needed. Model outages retain capture and report evaluation unavailable.

```sh
python3 -m pip install -e '.[dashboard]'
traceward run --goal "Diagnose the failing test" codex \
  --sandbox workspace-write -c sandbox_workspace_write.network_access=true exec "Run npm test and explain the failure"
```

On first use TraceWard pulls `ghcr.io/traceward/runner:0.2.0`, then reuses the cached image. Public publication is pending; until it is published, a failed default-image pull automatically builds the bundled recipe. First build needs network access and takes longer than cached launches. A custom runner pull failure does not silently substitute the default image.

All arguments after `codex` are forwarded unchanged. TraceWard options (`--runner-image`, `--workspace`, `--guest-image`, `--judge-provider`, `--judge-url`, `--judge-model`, `--goal-file`) precede `codex`. Interactive goal entry, terminal I/O, resizing, operator signals, working directory and exit status are preserved. This executes **Linux Codex**, not native macOS binaries.

The tested Codex configuration is explicit **workspace-write with network access**. Codex's default read-only/network-isolated Bubblewrap mode failed inside pinned gVisor host networking (`Failed to look up lo`). TraceWard does not silently disable Codex's sandbox or approvals. Native AMD64 execution awaits the native CI gate; emulated AMD64 on ARM64 is rejected because systrap failed under emulation. Rootless Docker and arbitrary pre-existing containers are unverified and unsupported in v1.

## Credentials and hooks

For **actual-agent adversarial evaluation**, the separately installed `traceward-pi eval` lab runs Pi with local Qwen in disposable repositories and measures receiver receipts, protected-state changes and task completion independently of TraceWard's judge. It also supports explicit actor-model comparisons. See [Pi evaluation harness](evaluation/pi/README.md) for cases, isolation, transcript handling, limitations and reproduction. This experimental Pi path uses a fresh home and Docker-isolated networking; the Codex credential/trust instructions below still apply to Codex runs.

The effective `CODEX_HOME`, or `~/.codex`, is mounted writable at `/codex-home`. Existing file-backed authentication is reused; refresh, configuration, history and hook trust persist. Keychain-only authentication is not portable: configure Codex `cli_auth_credentials_store = "file"` and sign in on the host if necessary. TraceWard does not extract Keychain secrets. Shared history can contain host paths unavailable in Linux; stale rollout-path warnings were observed. Host-specific MCP commands and tools may also be unavailable.

Start an interactive run once, open Codex `/hooks`, review and trust the three TraceWard handlers. The stable command is:

```text
PYTHONPATH=/opt/traceward-hooks /usr/local/bin/python3 -m traceward.hook_sink
```

TraceWard does not write trust hashes or bypass `/hooks`. Without trusted hooks, runtime observation continues with an explicit combined-coverage gap.

The workspace is mounted at its original absolute path, with external Git worktree metadata where needed. `--workspace` must contain the invoking working directory. The guest receives only the workspace, Codex home, hook log, read-only hook helper and startup gate. Observer credentials and evidence directories are excluded. If an observer `.env` file already lies inside the mounted workspace, TraceWard reports the overlap; it cannot conceal an existing workspace file. Avoid running an observed task in TraceWard's own checkout containing observer credentials.

The runner uses `SYS_ADMIN`, `SYS_PTRACE`, and unconfined Docker seccomp/AppArmor settings for nested systrap; it uses neither `--privileged` nor the Docker socket. Guest `SETUID`, `SETGID` and `SETFCAP` capabilities are emulated by gVisor to support Codex's nested user namespace.

## Custom dependencies and embedded execution

`--guest-image IMAGE` exports a trusted native Docker image into a cached root filesystem. It must contain Linux Codex and `/usr/local/bin/python3` for the bootstrap/hooks. For example, extend the managed guest filesystem:

```dockerfile
FROM ghcr.io/traceward/runner:0.2.0 AS managed
FROM scratch
COPY --from=managed /opt/traceward/rootfs/ /
RUN apt-get update && apt-get install -y --no-install-recommends make
```

```sh
traceward run --goal "Build the project" --guest-image project-agent:local codex <flags>
```

The same supervisor can execute embedded inside the configured managed runner with the required Docker capabilities. Running inside arbitrary existing containers, Docker-free execution and transparent native macOS process capture are outside v1.

## Evidence and analysis

Internal candidates and cleared/inconclusive decisions live in `assessments.jsonl`. Only review dispositions and explicit withdrawals enter `findings.jsonl`; the default dashboard and findings API show current review findings. The separate Assessment audit view retains complete diagnostic history, including historical cleared records. A finding is a supported concern requiring review, rather than every operation considered by the detector.

Owner-only runs live at `${XDG_STATE_HOME:-~/.local/state}/traceward/runs/<uuid>/`: `run.json`, `raw.gvisor.jsonl`, `hooks.jsonl`, `events.jsonl`, `findings.jsonl`, `evaluations.jsonl`, `runtime-status.json`, and `summary.json`. JSONL is authoritative. The dashboard's owner-only SQLite database is a rebuildable projection. Historical strace runs and attachments remain readable; live strace launchers, parsers and replay were removed.

The receiver validates SecCheck version-1 handshakes and bounded protobuf packets from pinned `release-20260928.0` schemas. A verified trace session releases the agent startup gate. Required telemetry failure prevents task startup; loss during execution marks coverage incomplete and lets the guest continue. Process identities use sandbox/PID/start time. Descriptor duplication, closure, inheritance, sharing and CLOEXEC support file/socket attribution. Positive returned byte counts establish effects; failures and asynchronous connection attempts remain distinct.

The runtime collector does not persist syscall read/write buffers, network payloads or environment values. Raw source records retain redacted metadata and stable line references. Shell commands, paths and hook metadata can still be sensitive. mmap coverage is incomplete, unresolved destinations and unsupported effects are gaps, and read followed by send does not prove transmission of those bytes. Hooks are agent-writable; this is not tamper-proof evidence. The optional Pi evaluation lab separately saves actual synthetic actor transcripts and receiver hashes; see [Pi evaluation harness](evaluation/pi/README.md) before sharing those artifacts.

The expanded pipeline creates investigations for workspace writes, host-observed repository changes, standalone sensitive reads, failed sensitive access or network attempts, independent network effects and access to operator-declared shared roots. Hook attribution strengthens an explanation; missing hooks do not discard independently observed effects. Candidates become alerts only after a review disposition. Incomplete attribution or omitted context prevents a reassuring clearance.

`--context-mode redacted` opts into bounded, locally redacted tool-result/session excerpts and selected file diffs. The default `metadata` mode retains hashes and metadata without those excerpts. Contents are labelled by source and trust; document claims and captured user-role messages cannot supersede the original CLI goal. Redaction is best effort, so redacted capture still requires local handling of potentially sensitive text.

Host baseline/final snapshots preserve sampled file identity and content versions. A local SQLite evidence graph connects tools, paths and sampled versions; path/time edges are inference. `--shared-root PATH` opts into cross-run version lookup for a shared directory in the workspace, without granting permissions. `traceward rebuild-graph` rebuilds the derived index from retained logs; deleted source records and uncollected versions cannot be recovered.

`--validation-script PATH` freezes an observer-selected checker outside the guest workspace and runs it in a separate read-only, network-isolated Docker invocation. `--permissions-file PATH` imports a bounded external permission log outside the observed workspace. Requests, denials, proposals and approvals retain identity, scope, expiry and revision when supplied. The adapter recognises OpenShell evidence shapes; no live OpenShell deployment or enforcement integration is implied. Missing fields remain missing. The evaluation lab's approval service is a synthetic application controller, not a runtime permission grant.

New packets use `goal-effects-v4`: relevance, authority, integrity, outcome, benign explanations and missing evidence have separate categorical assessments and citations. Observer-computed factual predicates check selected claims against event types, integrity flags and full hash/version matches. These checks do not prove natural-language entailment, intent, payload transmission or resistance to every injection. Semantic input is capped at 12 KiB; the complete factual-table user message at 14 KiB. Full packets and exact requests remain auditable. Legacy packets retain v3.

The judge runs on the invoking host. Defaults are `lmstudio`, `qwen/qwen3.8-27b`, and `http://127.0.0.1:1234/v1/chat/completions`. A supplied `/api/v1` base is normalized to this same server’s schema-capable OpenAI-compatible endpoint. TraceWard requests strict JSON with `disposition`, `evidence_ids`, and `rationale`; it validates model identity, completion and citations. Categorical results have **no numerical risk score**. Malformed, refused, truncated or unresolved answers are unavailable; no model fallback is used.

Set `TRACEWARD_JUDGE_PROVIDER`, `TRACEWARD_JUDGE_URL` and `TRACEWARD_JUDGE_MODEL` in the checkout `.env`, an explicit `TRACEWARD_ENV_FILE`, or process environment; CLI `--judge-*` overrides these settings. Environment wins over file settings. Optional endpoint authentication uses only `TRACEWARD_JUDGE_TOKEN`; the Unsloth token is never sent to LM Studio. Settings are stripped from the agent environment. The loaded server context is unchanged; Qwen receives bounded factual episodes of at most 8,192 UTF-8 bytes with a 1,600-token output limit and reasoning disabled. Full packets, exact requests/responses and alias/group mappings remain auditable. Pruning, ambiguity, outage and incomplete coverage prevent a clearing decision.

Legacy Laya remains explicitly selectable with `--judge-provider laya` (or `--laya-url`), using `TRACEWARD_LAYA_URL`, `TRACEWARD_LAYA_MODEL` and `UNSLOTH_TOKEN`. Its original 1,800-byte input budget and uncalibrated score thresholds are unchanged. Historical JSONL/API field `laya` holds model assessments for compatibility; inspect its actual `provider`, `model` and `status` rather than interpreting the field name as model provenance.

## Dashboard and validation

```sh
npm ci --prefix web
npm run build --prefix web
traceward dashboard
python3 -m unittest discover -s tests -q
TRACEWARD_TEST_DOCKER=1 python3 -m unittest discover -s tests -p test_gvisor_integration.py -q
npm run test:e2e --prefix web
```

Browser tests use Chrome by default; set `PLAYWRIGHT_CHANNEL` for another installed supported browser. They use explicitly synthetic decisions against real JSONL/API projections. Real six-case validation, actual decisions, UI inspection and measurements are documented in [DEMO.md](DEMO.md) and [VALIDATION.md](VALIDATION.md).

Replay preserves source attachments:

```sh
traceward replay --goal "Diagnose a test failure" --hooks hooks.jsonl --trace raw.gvisor.jsonl --abi arm64 --offline
```
