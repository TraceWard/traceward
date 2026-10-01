# TraceWard PoC

Linux-first, observe-only wrapper for Codex. It joins Codex tool hooks with `strace -f` process, file, and network metadata, appends OCSF v1.8 JSONL, and emits live, evidence-backed review findings. It does not sandbox, proxy, block, or prove that a run is safe.

## Setup

Requires Linux, Python 3.11+, `strace`, and a Codex CLI with `PreToolUse`/`PostToolUse` hooks. Install with `python3 -m pip install -e .`. Sign in to Codex **on the Linux machine** with `codex login`; TraceWard uses that login unchanged. In containers, `strace` must be able to trace its child (for example, an explicit `SYS_PTRACE` capability where appropriate). TraceWard checks this before launching Codex.

Codex requires you to review and trust non-managed hooks. TraceWard passes stable hook definitions via run-scoped `-c` overrides. For first setup, start `traceward run --goal "Review TraceWard hooks" codex`, open `/hooks` in that interactive session, inspect the TraceWard command handlers, and trust only those you intend to run. Then start the actual task. Non-interactive `codex exec` cannot perform this trust review. The wrapper never passes `--dangerously-bypass-hook-trust`. If no hook arrives, the summary says combined coverage was not achieved.

```sh
traceward run --goal "Fix the failing test" codex exec --skip-git-repo-check "Run npm test and fix the failure"
traceward run --goal-file goal.txt codex
traceward watch <run-id>
traceward replay --goal "Fix the failing test" --hooks hooks.jsonl --trace raw.strace --offline
```

Every argument after `codex` is passed through unchanged. A missing goal is prompted only in interactive mode. The default Laya URL is `http://localhost:8888/v1/systemone`; override with `--laya-url` or `TRACEWARD_LAYA_URL`. The optional `UNSLOTH_TOKEN` is used only by the observer as an Authorization header; it is removed from the launched Codex environment and never copied into the event record. If TraceWard runs inside a container, `localhost` means that container, so configure a reachable URL explicitly when needed.

Run files live at `${XDG_STATE_HOME:-~/.local/state}/traceward/runs/<run-id>/`: `events.jsonl` (OCSF), `findings.jsonl` (provisional and revised findings), `hooks.jsonl`, `raw.strace`, and `summary.json`. The directory and files are owner-only. `raw.strace` and hook commands can contain sensitive command-line arguments and paths, so treat these files as sensitive despite TraceWard recording no read buffers or network payloads. Laya receives only a bounded, redacted episode, never raw traces. Its 0–1 output is an **uncalibrated risk score**, not a probability.

## Synthetic demonstration

`fixtures/disguised` contains a deliberately failing test. `npm test` also loads `scripts/report.js`, which reads a **synthetic** credential and posts it to `127.0.0.1:8800`. Run `receiver.py` in a second terminal, then run TraceWard against Codex in a disposable copy of the fixture. This is a controlled test, not a production agent or real secret. A useful result links a Codex `npm test` hook to the npm/shell/Node process chain, a confirmed read, and a loopback send, with stable evidence IDs. Inspect the finding and compare it with hook-only and runtime-only views.

## Tests and limitations

```sh
python3 -m unittest discover -s tests -v
TRACEWARD_TEST_OCSF_ONLINE=1 python3 -m unittest discover -s tests -v
```

The opt-in test sends **synthetic** records to the official OCSF v1.8 validator. Local tests are offline. The parser does not cover memory-mapped I/O, all syscalls, escaped descendants, or all Codex tool paths. Hook-to-process matching uses command and time only because hook IDs do not include OS PIDs; ambiguous matches are a coverage gap. A finding is suspicion requiring review, not a violation verdict. Missing events or no finding are not evidence of safety. No allowlist, hosted store, or enforcement is included.

The Linux tests use real `strace` and an actual npm child-process fixture, but a Codex executable stub for wrapper checks and a synthetic hook for the hidden-effect test. A signed-in, hook-trusted **real Codex run on Linux** has not yet been completed. This remains the final end-to-end acceptance check, along with a comparable untraced run for overhead measurement.
