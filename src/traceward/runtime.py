"""Host-side managed runner setup. Docker is the only host prerequisite."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import OBSERVER_KEYS

RUNNER_IMAGE = "ghcr.io/traceward/runner:0.2.0"
HOOK_COMMAND = "PYTHONPATH=/opt/traceward-hooks /usr/local/bin/python3 -m traceward.hook_sink"


def hook_overrides() -> list[str]:
    handler = '{type="command",command=' + json.dumps(HOOK_COMMAND) + ',timeout=5}'
    return ["-c", f"hooks.SessionStart=[{{hooks=[{handler}]}}]",
            "-c", f'hooks.PreToolUse=[{{matcher="Bash|apply_patch",hooks=[{handler}]}}]',
            "-c", f'hooks.PostToolUse=[{{matcher="Bash|apply_patch",hooks=[{handler}]}}]']


def checked(command: list[str], **kwargs) -> str:
    result = subprocess.run(command, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{command[0]} setup failed: {result.stderr[-1500:]}")
    return result.stdout.strip()


def ensure_image(image: str) -> dict:
    if not shutil.which("docker"):
        raise RuntimeError("Docker is required; install/start Docker before running TraceWard")
    checked(["docker", "info", "--format", "{{.OSType}}"])
    probe = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    if probe.returncode:
        print(f"TraceWard: obtaining {image}…", file=sys.stderr, flush=True)
        pulled = subprocess.run(["docker", "pull", image])
        if pulled.returncode:
            # Source checkouts can bootstrap an unpublished development build.
            # Packaged releases include the same build recipe, so no runsc
            # download/configuration is delegated to the customer.
            if image != RUNNER_IMAGE:
                raise RuntimeError("runner image could not be pulled; check the image name and registry access")
            root = Path(__file__).resolve().parent
            with tempfile.TemporaryDirectory(prefix="traceward-build-") as tmp:
                context = Path(tmp)
                shutil.copytree(root, context / "src" / "traceward", ignore=shutil.ignore_patterns("__pycache__"))
                print("TraceWard: release image unavailable; building the bundled runtime automatically…",
                      file=sys.stderr, flush=True)
                if subprocess.run(["docker", "build", "-t", image, "-f",
                                   str(context / "src/traceward/runner_image/Dockerfile"), str(context)]).returncode:
                    raise RuntimeError("managed runner build failed; no Codex task was started")
    metadata = json.loads(checked(["docker", "image", "inspect", image]))[0]
    native = checked(["docker", "info", "--format", "{{.Architecture}}"])
    native = {"aarch64": "arm64", "x86_64": "amd64"}.get(native, native)
    if metadata["Architecture"] != native:
        raise RuntimeError("a native runner image is required; gVisor systrap cannot use cross-architecture Docker emulation")
    return metadata


def codex_home() -> Path:
    path = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))).expanduser().resolve()
    config = path / "config.toml"
    if config.exists():
        import tomllib
        mode = tomllib.loads(config.read_text()).get("cli_auth_credentials_store", "auto")
        if mode == "keyring":
            raise RuntimeError("Codex uses the host Keychain. Choose file credential storage in Codex and sign in "
                               "on the host; TraceWard cannot share a macOS Keychain with Linux")
    if not (path / "auth.json").is_file() and not os.environ.get("OPENAI_API_KEY"):
        raise RuntimeError("portable Codex credentials missing. Sign in to Codex on the host using file "
                           "credential storage; TraceWard will reuse that Codex home")
    if not os.access(path, os.W_OK):
        raise RuntimeError("Codex home must be writable for credential refresh and hook trust")
    return path


def workspace_root(cwd: Path, selected: str | None) -> tuple[Path, list[Path]]:
    root = Path(selected).expanduser().resolve() if selected else cwd
    result = subprocess.run(["git", "-C", str(cwd), "rev-parse", "--show-toplevel"],
                            capture_output=True, text=True)
    if not selected and result.returncode == 0:
        root = Path(result.stdout.strip()).resolve()
    if not root.is_dir() or not cwd.is_relative_to(root):
        raise ValueError("--workspace must be a directory containing the current working directory")
    extras = []
    if (root / ".git").is_file():
        common = checked(["git", "-C", str(root), "rev-parse", "--path-format=absolute", "--git-common-dir"])
        path = Path(common).resolve()
        if not path.is_relative_to(root):
            extras.append(path)
    return root, extras


class ManagedRuntime:
    def __init__(self, run_dir: Path, run_id: str, args: list[str], *,
                 image: str | None = None, workspace: str | None = None, guest_image: str | None = None):
        self.run_dir, self.container = run_dir, "traceward-" + run_id
        self.embedded = os.environ.get("TRACEWARD_MANAGED_RUNNER") == "1"
        self.image = image or os.environ.get("TRACEWARD_RUNNER_IMAGE", RUNNER_IMAGE)
        self.gaps = ["mmap-backed reads, unsupported syscalls and effects outside the guest are not fully observed",
                     "hook records are agent-writable; evidence is not tamper-proof",
                     "network metadata does not prove payload contents or sensitive-byte transmission"]
        cwd = Path.cwd().resolve()
        root, extras = workspace_root(cwd, workspace)
        home = codex_home()
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/codex-home", "CODEX_HOME": "/codex-home",
               "LANG": "C.UTF-8", "TERM": os.environ.get("TERM", "xterm-256color"),
               "TRACEWARD_RUN_ID": run_id, "TRACEWARD_HOOK_FILE": "/traceward-hooks/hooks.jsonl"}
        if os.environ.get("TRACEWARD_DEMO_CASE"):
            env["TRACEWARD_DEMO_CASE"] = os.environ["TRACEWARD_DEMO_CASE"]
            env["PYTHONPATH"] = "/opt/traceward-hooks"
        # Narrow agent environment, never observer settings or arbitrary host credentials.
        for key in ("OPENAI_API_KEY", "CODEX_API_KEY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"):
            if key in os.environ and key not in OBSERVER_KEYS:
                env[key] = os.environ[key]
        observer_file = Path(os.environ.get("TRACEWARD_ENV_FILE", str(Path(__file__).resolve().parents[2] / ".env"))).resolve()
        if observer_file.exists() and observer_file.is_relative_to(root):
            self.gaps.append("observer configuration file overlaps the mounted workspace; guest may read it")
        if run_dir.is_relative_to(root):
            raise ValueError("runs directory must be outside the workspace to keep evidence outside the guest")
        outer_mounts = [(root, str(root), True), *[(p, str(p), True) for p in extras],
                        (home, "/codex-home", True), (run_dir, "/observer-run", True)]
        guest_mounts = [(str(root), str(root), True), *[(str(p), str(p), True) for p in extras],
                        ("/codex-home", "/codex-home", True),
                        ("/observer-run/hooks.jsonl", "/traceward-hooks/hooks.jsonl", True),
                        ("/opt/traceward/src", "/opt/traceward-hooks", False)]
        self.metadata = {"runtime": "gvisor", "runner_image": self.image, "codex_version": "0.159.3",
                         "workspace": str(root), "guest_os": "Linux", "enforcement_actors": ["Docker", "gVisor", "Codex"]}
        self.command = [sys.executable, "-m", "traceward.runner", str(run_dir / "request.json")]
        rootfs = "/opt/traceward/rootfs"
        if self.embedded:
            guest_mounts = [(str(home) if source == "/codex-home" else
                             str(run_dir / "hooks.jsonl") if source.endswith("hooks.jsonl") else source,
                             target, writable) for source, target, writable in guest_mounts]
        else:
            inspected = ensure_image(self.image)
            self.metadata["runner_image_id"] = inspected["Id"]
            self.metadata["abi"] = inspected["Architecture"]
            self.command = ["docker", "run", "--rm", "--name", self.container,
                            "--cap-add=SYS_ADMIN", "--cap-add=SYS_PTRACE",
                            "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined", "-i"]
            if sys.stdin.isatty() and sys.stdout.isatty():
                self.command.append("-t")
            if guest_image:
                custom = ensure_image(guest_image)
                cache = run_dir.parent.parent / "images"
                cache.mkdir(parents=True, mode=0o700, exist_ok=True)
                archive = cache / (custom["Id"].split(":")[-1] + ".tar")
                if not archive.exists():
                    container = checked(["docker", "create", guest_image, "/bin/true"])
                    try:
                        temporary = archive.with_suffix(".tmp")
                        checked(["docker", "export", "-o", str(temporary), container])
                        temporary.chmod(0o600)
                        temporary.replace(archive)
                    finally:
                        checked(["docker", "rm", container])
                outer_mounts.append((archive, "/custom-rootfs.tar", False))
                rootfs = "/custom-rootfs"
                self.metadata["guest_image_id"] = custom["Id"]
            for source, target, writable in outer_mounts:
                if "," in str(source) or "," in target:
                    raise ValueError("Docker bind paths containing commas are unsupported")
                self.command += ["--mount", f"type=bind,source={source},target={target}" + ("" if writable else ",readonly")]
            self.command += ["--entrypoint", "/usr/local/bin/python3", self.image,
                             "-m", "traceward.runner", "/observer-run/request.json"]
        request = {"run_id": run_id, "cwd": str(cwd), "uid": os.getuid(), "gid": os.getgid(),
                   "command": ["codex", *hook_overrides(), *args], "env": env,
                   "guest_mounts": guest_mounts, "rootfs": rootfs,
                   "fixture_receiver": os.environ.get("TRACEWARD_FIXTURE_RECEIVER") == "1"}
        fd = os.open(run_dir / "request.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(request, stream)

    def signal(self, child, signum):
        if self.embedded:
            child.send_signal(signum)
        else:
            subprocess.run(["docker", "kill", "--signal", str(signum), self.container],
                           capture_output=True)

    def cleanup(self):
        (self.run_dir / "request.json").unlink(missing_ok=True)
        if not self.embedded:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
