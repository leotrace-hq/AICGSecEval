"""Container runtime for the A.S.E agent adapters (`--agent_runtime container`).

The default runtime (`host`) is the published one: the agent runs on this machine, Claude through
the Claude Agent SDK and Codex as `codex exec` in its workspace-write sandbox, and the corridor
arm runs Corridor on the host (bench/agent/_corridor.py, CorridorCell). The container runtime is
for the new A.S.E arms (sealed raw, corridor long-running and developer, commit-control): the
fork still prepares the cycle on the host exactly as before (copy, mask, seal, prompt), then
LeoBench's harness/container_agent.py runs the agent step inside the `leobench-cell` container,
the same machinery LeoBench's synthetic harness uses, and the fork continues as before (the
vuln-file check, extraction, records, verification later).

Nothing of Corridor runs on the host in this runtime: CorridorCell is never created, so the host
setup (prepare / _install / the setup scripts / the CLI) is never called. Corridor's install,
hooks, scans and plugin run only in the container. The host does run git on the cycle repo (the
origin label, rev-parse, the diff), never a commit, and LeoBench renames the repo's Corridor
pre-commit hook once the agent is done.

Records, beside the cycle dir in `_security/<cycle>/` (the paths LeoBench's A.S.E reports read):
  corridor_review.json   LeoBench's classify_corridor record (the synthetic meta.corridor_review
                         keys) plus restored_original (computed here, against the sealed base),
                         tool (provenance) and runtime
  commit_control.json    {mode, committed, project_repo} plus restored_original and runtime
  container_agent.json   LeoBench's full result (status, returncode, image, tool policy, ...)
  conversation.txt, result.diff, and LeoBench's per-cell dirs (_claude, _codex, _corridor,
  _corridor-obs)

Secrets stay in the environment: CLAUDE_CODE_OAUTH_TOKEN (or $LEOPREVENT_ENV_FILE), the staged
Codex auth.json, CORRIDOR_API_KEY. Nothing secret is put on the LeoBench command line.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

from bench.agent import _corridor

ARMS = ("raw", "corridor", "commit-control")
AUTHS = ("subscription", "api-key")
# TESTS ONLY: a stub script run in the container instead of the agent (no model). Every record of
# a cell run this way says stub_agent: true.
STUB_ENV = "ASE_CONTAINER_STUB_AGENT"


class ContainerRuntimeError(RuntimeError):
    pass


def leobench_entry(leobench_home):
    """harness/container_agent.py in the LeoBench checkout ($LEOBENCH_HOME), or raise."""
    if not leobench_home:
        raise ContainerRuntimeError("--agent_runtime container needs the LeoBench checkout: set "
                                    "$LEOBENCH_HOME or pass --leobench_home")
    entry = Path(leobench_home) / "harness" / "container_agent.py"
    if not entry.is_file():
        raise ContainerRuntimeError(f"no harness/container_agent.py under {leobench_home}")
    return entry


def add_args(parser):
    """--agent_runtime and --leobench_home, shared by the Claude and Codex adapters."""
    parser.add_argument("--agent_runtime", type=str, choices=["host", "container"], default="host",
                        help="host = the agent runs on this machine (the published A.S.E runs); "
                             "container = the agent step runs in LeoBench's cell container "
                             "(raw, corridor and commit-control only; see bench/agent/_container.py)")
    parser.add_argument("--leobench_home", type=str, default=os.environ.get("LEOBENCH_HOME"),
                        help="LeoBench checkout for --agent_runtime container (default $LEOBENCH_HOME)")


class ContainerRuntime:
    """One cycle's agent step in a LeoBench cell container."""

    def __init__(self, agent, arm, mode, repo_dir, model, logger, *, effort=None,
                 auth="subscription", env_file=None, corridor_dist=None, leobench_home=None,
                 claude_policy=None, timeout=None):
        if agent not in ("claude", "codex"):
            raise ContainerRuntimeError(f"unknown agent {agent!r}")
        if arm not in ARMS:
            raise ContainerRuntimeError(
                f"--agent_runtime container runs the new A.S.E arms only ({', '.join(ARMS)}); "
                f"arm {arm!r} stays on the host runtime")
        if auth not in AUTHS:
            raise ContainerRuntimeError(f"--agent_runtime container supports --auth "
                                        f"{' or '.join(AUTHS)}, not {auth!r}")
        if not model:
            raise ContainerRuntimeError("--agent_runtime container needs the model named")
        self.agent, self.arm, self.mode, self.model = agent, arm, mode, model
        self.repo = Path(repo_dir)
        self.state = _corridor.state_dir_for(repo_dir)
        self.logger = logger
        self.effort, self.auth, self.env_file = effort, auth, env_file
        self.corridor_dist = corridor_dist
        self.leobench_home = leobench_home or os.environ.get("LEOBENCH_HOME")
        self.claude_policy = claude_policy or {}
        self.timeout = timeout
        self.project_repo = _corridor.project_for_repo(repo_dir) if arm in _corridor.ARMS else None
        self.result = None

    def check(self):
        """Fail before any cycle runs: LeoBench present, Corridor key and staged dist on the
        corridor arm (the key is checked by name, never read into a record)."""
        leobench_entry(self.leobench_home)
        if self.arm == "corridor":
            if not os.environ.get(_corridor.API_KEY_ENV) and not _env_file_has(
                    self.env_file, _corridor.API_KEY_ENV):
                raise ContainerRuntimeError(f"--arm corridor needs {_corridor.API_KEY_ENV} in the "
                                            f"environment")
            if not self.corridor_dist:
                raise ContainerRuntimeError("--arm corridor needs the staged Linux Corridor "
                                            "distribution ($CORRIDOR_DIST_DIR)")

    def command(self, prompt_file, system_prompt_file, result_file):
        """The LeoBench command line. Paths and choices only: no secret is ever on it."""
        cmd = [sys.executable, str(leobench_entry(self.leobench_home)), "run",
               "--work", str(self.repo), "--state", str(self.state), "--agent", self.agent,
               "--model", self.model, "--arm", self.arm, "--prompt-file", str(prompt_file),
               "--auth", self.auth, "--result", str(result_file)]
        if self.mode:
            cmd += ["--corridor-mode", self.mode]
        if self.effort:
            cmd += ["--effort", self.effort]
        if self.project_repo:
            cmd += ["--project-repo", self.project_repo]
        if self.arm == "corridor":
            cmd += ["--corridor-dist", str(self.corridor_dist)]
        if self.env_file:
            cmd += ["--env-file", str(self.env_file)]
        if self.timeout:
            cmd += ["--timeout", str(int(self.timeout))]
        if self.agent == "claude":
            p = self.claude_policy
            if "allowed_tools" in p:
                cmd += ["--claude-allowed-tools", ",".join(p["allowed_tools"])]
            if "disallowed_tools" in p:
                cmd += ["--claude-disallowed-tools", ",".join(p["disallowed_tools"])]
            if p.get("permission_mode"):
                cmd += ["--claude-permission-mode", p["permission_mode"]]
            if "setting_sources" in p:
                cmd += ["--claude-setting-sources", ",".join(p["setting_sources"])]
            if system_prompt_file:
                cmd += ["--claude-system-prompt-file", str(system_prompt_file)]
        stub = os.environ.get(STUB_ENV)
        if stub:
            cmd += ["--stub-agent", stub]
        return cmd

    def run(self, prompt, vuln_file):
        """Run the agent step; write the cycle's records; return True when the agent exited 0."""
        base = _git_out(self.repo, "rev-parse", "HEAD")
        self.state.mkdir(parents=True, exist_ok=True)
        prompt_file = self.state / "prompt.txt"
        prompt_file.write_text(prompt, encoding="utf-8")
        sp_file = None
        if self.agent == "claude" and self.claude_policy.get("system_prompt") is not None:
            sp_file = self.state / "system_prompt.txt"
            sp_file.write_text(self.claude_policy["system_prompt"], encoding="utf-8")
        result_file = self.state / "container_agent.result.json"
        if result_file.exists():
            result_file.unlink()
        cmd = self.command(prompt_file, sp_file, result_file)
        self.logger.info(f"container agent ({self.agent}, {self.arm}"
                         + (f", {self.mode}" if self.mode else "") + f"): {self.repo}")
        r = subprocess.run(cmd, capture_output=True, text=True, stdin=subprocess.DEVNULL)
        for line in (r.stdout + r.stderr).splitlines()[-40:]:
            self.logger.info(f"container agent: {_corridor.redact(line)}")
        try:
            res = json.loads(result_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            res = {"error": f"container_agent.py exited {r.returncode} without a result"}
        self.result = res
        if res.get("error"):
            if self.arm == "corridor":
                review = _corridor.empty_review(self.mode, self.agent)
                review.update({"installed": False, "project_repo": self.project_repo,
                               "restored_original": False, "runtime": "container",
                               "reason": f"not run: {res['error']}"})
                self._write("corridor_review.json", review)
            raise ContainerRuntimeError(f"container agent step failed: {res['error']}")
        restored = _corridor.restored_original(self.repo, base, vuln_file)
        extra = {"restored_original": restored, "runtime": "container",
                 "stub_agent": bool(res.get("stub_agent"))}
        if self.arm == "corridor":
            review = dict(res.get("corridor_review") or {})
            review.update(extra)
            review["tool"] = res.get("tool") or {}
            self._write("corridor_review.json", review)
            self.logger.info(f"corridor record: {review.get('reason')}")
        elif self.arm == "commit-control":
            rec = dict(res.get("commit_control") or {})
            rec.update(extra)
            self._write("commit_control.json", rec)
        self.logger.info(f"container agent status={res.get('status')} rc={res.get('returncode')} "
                         f"elapsed={res.get('elapsed_s')}s")
        return res.get("returncode") == 0

    def _write(self, name, record):
        (self.state / name).write_text(_corridor.redact(json.dumps(record, indent=2)),
                                       encoding="utf-8")


def _git_out(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                       stdin=subprocess.DEVNULL)
    return r.stdout.strip() if r.returncode == 0 else None


def _env_file_has(path, name):
    if not path or not os.path.isfile(path):
        return False
    with open(path, encoding="utf-8", errors="replace") as f:
        return any(line.strip().startswith(f"{name}=") and line.strip() != f"{name}="
                   for line in f)
