# Sample Pi development environment

This is a Linux guest image for Pi under TraceWard's managed gVisor runtime. It includes Pi 0.85.1, Python 3.11 and pip, Node.js 22 and npm, Bash, Git, curl, jq, ripgrep, unzip and C/C++ build tools. It does not copy your project or credentials into the image.

From the TraceWard repository root:

```sh
docker build --tag traceward-pi-dev:local examples/pi-dev
```

Run from the project directory you want Pi to work in, with the TraceWard stack running and the actor model available on LM Studio. Configure the judge on the backend as described in the [setup guide](../../docs/backend.md).

```sh
traceward run --traceward-url http://localhost:8765 \
  --guest-image traceward-pi-dev:local \
  --pi-network bridge \
  --pi-model qwen3.8-27b-uncensored \
  --pi-url http://127.0.0.1:1234/v1/chat/completions \
  pi "Inspect this project and explain how to run its tests."
```

Activate the checkout's virtual environment so `traceward` is on your path. The current directory and its containing workspace are mounted into the guest. Execution uses Linux binaries, not programs installed on macOS. TraceWard supplies its observer code and the model relay separately from this guest image.

If you configured a `tpi` shell helper, select the same options before any Pi arguments:

```sh
source ~/.zshrc
tpi --guest-image traceward-pi-dev:local --pi-network bridge \
  --goal "Inspect the project and explain its test workflow without changing files" \
  "Start by reading README.md"
```

To open Pi first and type the command in its chat, including HTTPS inspection:

```sh
tpi --guest-image traceward-pi-dev:local --pi-network bridge --pi-inspect-https \
  --goal "Execute test.sh once. Do not modify files or perform any network requests."
```

Then submit `Execute test.sh` inside Pi. The goal describes what is authorised; it does not block the script's network request. TraceWard observes it and assesses the conflict. Pending analysis and review findings update while Pi remains open.

The public per-run CA is installed into guest system trust automatically. Common curl, Python and Node trust settings are also inherited; no `--insecure` or per-command CA flag is needed. The CA key stays outside the guest and macOS trust is unchanged. Clients must use the supplied proxy; custom trust stores and pinning need separate handling. See [coverage and content limits](../../docs/runtime.md#https-inspection-for-pi).

`--goal` and `--goal-file` remain optional. Without either override, the initial instruction is the observation goal. If you supply no launch instruction, Pi opens directly and its first interactive chat becomes that goal.

`--pi-network bridge` explicitly enables Docker's default bridge networking, including outbound access and Docker-reachable services. Docker and gVisor provide the runtime boundary; TraceWard observes the resulting activity. The model still uses the fixed host relay. This is not a destination allowlist or an OpenShell policy proxy. Omit the option or select `--pi-network none` for the default loopback-only environment. Evaluation commands retain `none` and the original lab image.

The guest root filesystem stays read-only under TraceWard. The mounted workspace, fresh `/pi-home`, `/tmp` and `/run` are writable. Install project dependencies into a workspace virtual environment or local `node_modules`; add system packages to this Dockerfile and rebuild. To add another dependency, extend the `apt-get install` list or add an image-build step.

For a curl smoke test, create a disposable project containing:

```sh
#!/bin/bash
curl --fail --show-error --silent --max-time 20 \
  --output /dev/null --write-out 'HTTP %{http_code}\n' https://example.com
```

Then, from that directory:

```sh
tpi --guest-image traceward-pi-dev:local --pi-network bridge \
  --goal "Run bash test.sh once. Its GET request to https://example.com is authorised. Do not edit files." \
  --print "Run bash test.sh once and report its result."
```

The request should print `HTTP 200`. Inspect the run's events, assessment audit and coverage in the dashboard. A successful request verifies this development setup, not detector accuracy or complete network coverage.
