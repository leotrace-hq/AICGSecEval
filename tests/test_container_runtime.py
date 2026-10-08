"""--agent_runtime container: the agent step in LeoBench's cell container.

Two layers:

  ContainerRuntimeFakeDocker   the whole chain (adapter -> bench/agent/_container.py -> LeoBench's
                               harness/container_agent.py -> run_cell.docker_command) with a FAKE
                               `docker` first on PATH that records every argv and answers exit 0.
                               No container, no model, no Corridor.
  ContainerRuntimeE2E          a REAL container (leobench-cell image) with a stub agent script in
                               place of the model and LeoBench's FAKE Corridor dist
                               (tests/fixtures/corridor_dist: a stand-in CLI plus copies of the
                               v0.0.87 setup scripts). Opt-in: ASE_CONTAINER_E2E=1.

Both need the LeoBench checkout: $LEOBENCH_HOME (skipped without it).
"""
import asyncio
import hashlib
import json
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from bench.agent import _container  # noqa: E402
from bench.agent import _corridor  # noqa: E402
from bench.agent import claude_code  # noqa: E402
from bench.agent import codex  # noqa: E402
from bench.utils import seal_task_repo  # noqa: E402

LEOBENCH = os.environ.get("LEOBENCH_HOME")
LOG = logging.getLogger("container-test")
TOKEN = "fake-oauth-SECRET-0123456789"
KEY = "fake-corridor-SECRET-0123456789"
ORIGINAL = "def f(x):\n    return x + 1\n"
MASKED = "def f(x):\n    <MASKED>\n"
GENERATED = "def f(x):\n    return x + 2\n"
PROJECT = "ase-capsa-cve-2022-21675"          # in LeoBench's Corridor manifest

FAKE_DOCKER = r'''#!{python}
import json, os, sys
argv = sys.argv[1:]
names = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "-e" and "=" not in argv[i + 1]]
with open(os.environ["FAKE_DOCKER_LOG"], "a") as f:
    f.write(json.dumps({"argv": argv, "forwarded": {n: n in os.environ for n in names}}) + "\n")
'''


def git(repo, *args, check=True):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=check)


def make_cycle(root, batch, name):
    """A cycle repo as A.S.E leaves it: upstream base, function masked, sealed."""
    repo = Path(root) / "generated_code" / batch / name
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    (repo / "app.py").write_text(ORIGINAL)
    git(repo, "add", "app.py")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base")
    (repo / "app.py").write_text(MASKED)
    seal_task_repo(repo, "app.py", MASKED)
    return repo


def adapter_args(agent, arm, mode, extra=()):
    argv = ["--arm", arm, "--agent_runtime", "container", "--leobench_home", LEOBENCH, *extra]
    if mode:
        argv += ["--corridor_mode", mode]
    if agent == "claude":
        return claude_code.ClaudeCodeAgentBench.parse_args(
            argv + ["--claude_model", "claude-test"])
    return codex.CodexAgentBench.parse_args(argv + ["--codex_model", "gpt-test",
                                                    "--codex_effort", "medium"])


def run_adapter(agent, repo, args):
    cls = claude_code.ClaudeCodeAgentBench if agent == "claude" else codex.CodexAgentBench
    bench = cls(LOG, str(repo), args)

    async def go():
        await bench.start()
        ok = await bench.generate_code("app.py", "adds one", ["ctx.py"])
        await bench.stop()
        return ok
    return bench, asyncio.run(go())


class _NoHostCorridor:
    """Any use of the host-side Corridor implementation fails the test."""

    def __init__(self, *a, **k):
        raise AssertionError("host-side CorridorCell created in container mode")


@unittest.skipUnless(LEOBENCH and os.path.isfile(os.path.join(LEOBENCH or "", "harness",
                                                               "container_agent.py")),
                     "set LEOBENCH_HOME to a LeoBench checkout with harness/container_agent.py")
class ContainerRuntimeFakeDocker(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="ase-container-")))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        bindir = self.tmp / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(FAKE_DOCKER.replace("{python}", sys.executable))
        docker.chmod(docker.stat().st_mode | stat.S_IEXEC)
        self.log = self.tmp / "docker.jsonl"
        home = self.tmp / "home"
        (home / ".codex").mkdir(parents=True)
        (home / ".codex" / "auth.json").write_text(json.dumps({"auth_mode": "chatgpt"}))
        self.dist = None
        env = {"PATH": f"{bindir}:{os.environ['PATH']}", "HOME": str(home),
               "FAKE_DOCKER_LOG": str(self.log), "CLAUDE_CODE_OAUTH_TOKEN": TOKEN,
               "CORRIDOR_API_KEY": KEY, "CORRIDOR_LOCK_DIR": str(self.tmp / "locks"),
               "LEOBENCH_ACCOUNT": "test", "LEOBENCH_PLATFORM": "linux/arm64",
               "LEOBENCH_SANDBOX_IMAGE": "leobench-cell:test"}
        for k in ("LEOPREVENT_ENV_FILE", "CORRIDOR_DIST_DIR", "CORRIDOR_MODE", _container.STUB_ENV):
            env[k] = ""
        p = mock.patch.dict(os.environ, env)
        p.start()
        self.addCleanup(p.stop)
        for k in ("LEOPREVENT_ENV_FILE", "CORRIDOR_DIST_DIR", "CORRIDOR_MODE", _container.STUB_ENV):
            os.environ.pop(k, None)
        p2 = mock.patch.object(_corridor, "CorridorCell", _NoHostCorridor)
        p2.start()
        self.addCleanup(p2.stop)
        self.leobench_calls = []
        real = subprocess.run

        def spy(cmd, *a, **kw):
            if isinstance(cmd, list) and any(str(x).endswith("container_agent.py") for x in cmd):
                self.leobench_calls.append([str(x) for x in cmd])
            return real(cmd, *a, **kw)
        p3 = mock.patch.object(_container.subprocess, "run", spy)
        p3.start()
        self.addCleanup(p3.stop)

    def staged_dist(self):
        fixture = os.path.join(LEOBENCH, "tests", "fixtures", "corridor_dist")
        r = subprocess.run([sys.executable, os.path.join(LEOBENCH, "harness", "container_agent.py"),
                            "stage-corridor", fixture, str(self.tmp / "out")],
                           capture_output=True, text=True, check=True)
        return r.stdout.strip()

    def docker_runs(self):
        rows = [json.loads(line) for line in self.log.read_text().splitlines()]
        return [r for r in rows if r["argv"][:1] == ["run"] and "--name" in r["argv"]
                and not r["argv"][r["argv"].index("--name") + 1].endswith("-prime")]

    def all_text(self):
        out = [self.log.read_text()] + [" ".join(c) for c in self.leobench_calls]
        for p in self.tmp.rglob("*"):
            if p.is_file() and not p.is_symlink() and "home" not in p.parts:
                out.append(p.read_bytes().decode(errors="replace"))
        return "\n".join(out)

    def test_claude_raw(self):
        repo = make_cycle(self.tmp, "claude_code__claude_raw_sealed", "Capsa_CVE-2022-21675_cycle1")
        bench, ok = run_adapter("claude", repo, adapter_args("claude", "raw", None))
        self.assertTrue(ok)
        (run,) = self.docker_runs()
        argv, joined = run["argv"], " ".join(run["argv"])
        self.assertIn(f"{repo}:{repo}", argv)                  # same absolute path
        self.assertEqual(argv[argv.index("-w") + 1], str(repo))
        self.assertEqual(run["forwarded"], {"CLAUDE_CODE_OAUTH_TOKEN": True})
        self.assertNotIn("--dangerously-skip-permissions", joined)
        self.assertIn("--allowedTools Read,Write,Edit,Grep --disallowedTools 'Bash(rm*)' "
                      "--permission-mode acceptEdits --setting-sources=", joined)
        self.assertIn("--system-prompt", joined)
        self.assertIn(claude_code.ASE_SYSTEM_PROMPT, joined)
        self.assertNotIn("Bash(git:*)", joined)
        self.assertNotIn(_corridor.COMMIT_INSTRUCTION, joined)
        self.assertIn("leobench-cell:test", argv)
        state = _corridor.state_dir_for(repo)
        res = json.loads((state / "container_agent.json").read_text())
        self.assertEqual((res["runtime"], res["arm"], res["returncode"]), ("container", "raw", 0))
        self.assertFalse((state / "corridor_review.json").exists())
        for secret in (TOKEN, KEY):
            self.assertNotIn(secret, self.all_text())

    def test_claude_corridor_long_running_record(self):
        dist = self.staged_dist()
        repo = make_cycle(self.tmp, "claude_code__claude_corridor_lr", "Capsa_CVE-2022-21675_cycle1")
        bench, ok = run_adapter("claude", repo, adapter_args(
            "claude", "corridor", "long-running", ["--corridor_dist_dir", dist]))
        (run,) = self.docker_runs()
        joined = " ".join(run["argv"])
        self.assertEqual(run["forwarded"], {"CLAUDE_CODE_OAUTH_TOKEN": True,
                                            "CORRIDOR_API_KEY": True})
        self.assertIn(f"CORRIDOR_HOOK_BASES={repo}", run["argv"])
        self.assertIn("/corridor-dist/setup/claude-setup.sh", joined)
        self.assertIn("unset CORRIDOR_API_KEY", joined)
        self.assertIn("--allowedTools 'Read,Write,Edit,Grep,Bash(git:*)'", joined)
        self.assertIn("--setting-sources=user", joined)
        self.assertIn(_corridor.COMMIT_INSTRUCTION, joined)
        self.assertEqual(git(repo, "remote", "get-url", "origin").stdout.strip(),
                         _corridor.PROJECT_URL.format(repo=PROJECT))
        review = json.loads((_corridor.state_dir_for(repo) / "corridor_review.json").read_text())
        # LeoBench's classifier keys, plus the fork's restored_original, tool and runtime.
        for k in _corridor.empty_review("long-running", "claude"):
            self.assertIn(k, review)
        self.assertEqual(review["project_repo"], PROJECT)
        self.assertFalse(review["installed"])           # the fake docker installed nothing
        self.assertTrue(review["restored_original"])    # vuln file still the sealed one
        self.assertEqual((review["runtime"], review["tool"]["tool"]), ("container", "corridor"))
        self.assertFalse(review["stub_agent"])
        for secret in (TOKEN, KEY):
            self.assertNotIn(secret, self.all_text())

    def test_codex_commit_control_and_developer(self):
        repo = make_cycle(self.tmp, "codex__codex_commitctl", "Capsa_CVE-2022-21675_cycle1")
        bench, ok = run_adapter("codex", repo, adapter_args("codex", "commit-control", None))
        (run,) = self.docker_runs()
        joined = " ".join(run["argv"])
        self.assertIn("codex exec", joined)
        self.assertIn("web_search=", joined)
        self.assertIn("model_reasoning_effort=", joined)
        self.assertEqual(run["forwarded"], {"CODEX_HOME": True})
        state = _corridor.state_dir_for(repo)
        self.assertIn(f"{state}/_codex:/home/cell/.codex", run["argv"])
        rec = json.loads((state / "commit_control.json").read_text())
        self.assertEqual({k: rec[k] for k in ("mode", "committed", "project_repo",
                                              "restored_original", "runtime")},
                         {"mode": "commit-control", "committed": False, "project_repo": PROJECT,
                          "restored_original": True, "runtime": "container"})
        dist = self.staged_dist()
        self.log.unlink()
        repo = make_cycle(self.tmp, "codex__codex_corridor_dev", "Capsa_CVE-2022-21675_cycle1")
        run_adapter("codex", repo, adapter_args("codex", "corridor", "developer",
                                                ["--corridor_dist_dir", dist]))
        (run,) = self.docker_runs()
        self.assertIn("corridor install -y", " ".join(run["argv"]))
        self.assertIn("mcp_servers", " ".join(run["argv"]))

    def test_restored_original_is_computed_against_the_sealed_base(self):
        repo = make_cycle(self.tmp, "claude_code__claude_commitctl", "Capsa_CVE-2022-21675_cycle1")
        rt = _container.ContainerRuntime("claude", "commit-control", None, repo, "m", LOG,
                                         leobench_home=LEOBENCH)

        real = subprocess.run

        def fake(cmd, *a, **kw):
            if "--result" not in cmd:
                return real(cmd, *a, **kw)                    # the host's own git calls
            (repo / "app.py").write_text(GENERATED)           # the agent wrote its code
            Path(cmd[cmd.index("--result") + 1]).write_text(json.dumps(
                {"returncode": 0, "commit_control": {"mode": "commit-control", "committed": True,
                                                     "project_repo": PROJECT}}))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        with mock.patch.object(_container.subprocess, "run", fake):
            self.assertTrue(rt.run("prompt", "app.py"))
        rec = json.loads((rt.state / "commit_control.json").read_text())
        self.assertFalse(rec["restored_original"])
        self.assertTrue(rec["committed"])

    def test_refusals(self):
        repo = make_cycle(self.tmp, "claude_code__x", "Capsa_CVE-2022-21675_cycle1")
        for arm in ("leoprevent", "security-guidance"):
            with self.assertRaises(_container.ContainerRuntimeError):
                claude_code.ClaudeCodeAgentBench(LOG, str(repo), adapter_args("claude", arm, None))
        with self.assertRaises(_container.ContainerRuntimeError):
            claude_code.ClaudeCodeAgentBench(LOG, str(repo), adapter_args(
                "claude", "raw", None, ["--auth", "bedrock"]))
        bench = claude_code.ClaudeCodeAgentBench(LOG, str(repo), adapter_args(
            "claude", "corridor", "developer"))
        with self.assertRaises(_container.ContainerRuntimeError):   # no staged dist
            asyncio.run(bench.start())

    def test_host_runtime_is_the_default(self):
        args = claude_code.ClaudeCodeAgentBench.parse_args(["--arm", "raw"])
        self.assertEqual(args.agent_runtime, "host")
        args = codex.CodexAgentBench.parse_args(["--arm", "raw"])
        self.assertEqual(args.agent_runtime, "host")


def _tree_hash(path):
    p = Path(path)
    if not p.exists():
        return None
    if p.is_file():
        return hashlib.sha256(p.read_bytes()).hexdigest()
    h = hashlib.sha256()
    for f in sorted(p.rglob("*")):
        h.update(str(f.relative_to(p)).encode())
        if f.is_file():
            h.update(f.read_bytes())
    return h.hexdigest()


HOST_FILES = [os.path.expanduser("~/.gitconfig"), "/etc/gitconfig",
              os.path.expanduser("~/.config/husky"), os.path.expanduser("~/.corridor"),
              os.path.expanduser("~/.config/git/config")]

STUB = """set -e
python3 -c "p='app.py'; s=open(p).read(); open(p,'w').write(s.replace('<MASKED>', 'return x + 2'))"
git add -A
git commit -q -m 'complete f'
git log -1 --format='%an <%ae>' > /home/cell/.claude/stub-identity.txt
echo stub agent done
"""

# The fake Corridor CLI blocks a staged diff containing VULN_MARKER, with the real block text.
STUB_BLOCKED = """python3 -c "p='app.py'; s=open(p).read(); open(p,'w').write(s.replace('<MASKED>', 'return x + 2  # VULN_MARKER'))"
git add -A
git commit -q -m 'complete f' || echo commit blocked
"""


@unittest.skipUnless(os.environ.get("ASE_CONTAINER_E2E") == "1" and LEOBENCH,
                     "real-Docker smoke: set ASE_CONTAINER_E2E=1 and LEOBENCH_HOME")
class ContainerRuntimeE2E(unittest.TestCase):
    """A real cell container, a stub agent (no model), LeoBench's FAKE Corridor dist."""

    def test_corridor_long_running_and_commit_control_in_docker(self):
        tmp = Path(os.path.realpath(tempfile.mkdtemp(prefix="ase-container-e2e-")))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        before = {f: _tree_hash(f) for f in HOST_FILES}
        stub = tmp / "stub.sh"
        stub.write_text(STUB)
        dist = subprocess.run([sys.executable, os.path.join(LEOBENCH, "harness", "container_agent.py"),
                               "stage-corridor", os.path.join(LEOBENCH, "tests", "fixtures",
                                                              "corridor_dist"), str(tmp / "out")],
                              capture_output=True, text=True, check=True).stdout.strip()
        env = {"CLAUDE_CODE_OAUTH_TOKEN": TOKEN, "CORRIDOR_API_KEY": KEY,
               "CORRIDOR_LOCK_DIR": str(tmp / "locks"), _container.STUB_ENV: str(stub),
               "LEOBENCH_ACCOUNT": "e2e",
               "LEOBENCH_SANDBOX_IMAGE": os.environ.get("LEOBENCH_SANDBOX_IMAGE",
                                                        "leobench-cell:run-451eeea")}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(_corridor, "CorridorCell", _NoHostCorridor):
            for k in ("LEOPREVENT_ENV_FILE", "CORRIDOR_DIST_DIR", "CORRIDOR_MODE"):
                os.environ.pop(k, None)
            results = {}
            blocking = tmp / "stub-blocked.sh"
            blocking.write_text(STUB_BLOCKED)
            for key, batch, arm, mode, script in (
                    ("corridor", "claude_code__claude_corridor_lr", "corridor", "long-running", stub),
                    ("commit-control", "claude_code__claude_commitctl", "commit-control", None, stub),
                    ("blocked", "claude_code__claude_corridor_lr2", "corridor", "long-running",
                     blocking)):
                os.environ[_container.STUB_ENV] = str(script)
                repo = make_cycle(tmp, batch, "Capsa_CVE-2022-21675_cycle1")
                extra = ["--corridor_dist_dir", dist] if arm == "corridor" else []
                bench, ok = run_adapter("claude", repo, adapter_args("claude", arm, mode, extra))
                results[key] = (repo, ok)
        after = {f: _tree_hash(f) for f in HOST_FILES}
        self.assertEqual(before, after, "a host git/husky/corridor config changed")

        repo, ok = results["corridor"]
        state = _corridor.state_dir_for(repo)
        res = json.loads((state / "container_agent.json").read_text())
        self.assertTrue(ok, res)
        # Extraction: the generated function is in the cycle's vuln file on the host.
        self.assertEqual((repo / "app.py").read_text(), GENERATED)
        review = json.loads((state / "corridor_review.json").read_text())
        self.assertTrue(review["installed"], review)
        self.assertTrue(review["valid"], review)
        self.assertTrue(review["committed"])
        self.assertEqual(review["scans"], 1, review)          # the pre-commit hook ran (trace2)
        self.assertEqual(review["blocked_commits"], 0)
        self.assertFalse(review["restored_original"])
        self.assertTrue(review["stub_agent"])
        self.assertEqual(review["project_repo"], PROJECT)
        self.assertEqual((state / "_claude" / "stub-identity.txt").read_text().strip(),
                         "LeoBench Agent <agent@leobench.invalid>")
        # The repo's Corridor hook is disabled once the agent is done, so a later host commit
        # in the cycle repo can never run Corridor here.
        self.assertFalse((repo / ".git" / "hooks" / "pre-commit").exists())
        self.assertTrue((repo / ".git" / "hooks" / "pre-commit.leobench-disabled").exists())
        # Corridor's state is the cell's, never the host's.
        self.assertTrue((state / "_corridor" / "config.env").is_file())
        self.assertIn("<REDACTED>", (state / "_corridor" / "config.env").read_text())
        for p in state.rglob("*"):
            if p.is_file():
                self.assertNotIn(KEY, p.read_bytes().decode(errors="replace"), p)
                self.assertNotIn(TOKEN, p.read_bytes().decode(errors="replace"), p)
        # Files the container wrote are the host user's (Docker Desktop's uid mapping).
        self.assertEqual((repo / "app.py").stat().st_uid, os.getuid())

        # A commit Corridor blocks: the pre-commit hook exits 1 (git trace2), nothing committed.
        repo, ok = results["blocked"]
        review = json.loads((_corridor.state_dir_for(repo) / "corridor_review.json").read_text())
        self.assertEqual((review["scans"], review["blocked_commits"], review["committed"]),
                         (1, 1, False), review)
        self.assertTrue(review["valid"])

        repo, ok = results["commit-control"]
        self.assertTrue(ok)
        rec = json.loads((_corridor.state_dir_for(repo) / "commit_control.json").read_text())
        self.assertEqual((rec["committed"], rec["restored_original"], rec["stub_agent"]),
                         (True, False, True))
        self.assertEqual((repo / "app.py").read_text(), GENERATED)

    def test_claude_cli_accepts_the_ase_policy_flags(self):
        """The image's Claude Code CLI knows every flag the A.S.E policy passes (an unknown flag
        would fail every cell). Enforcement itself needs a model; see the report."""
        image = os.environ.get("LEOBENCH_SANDBOX_IMAGE", "leobench-cell:run-451eeea")
        r = subprocess.run(["docker", "run", "--rm", "--name", "ase-e2e-claude-help",
                            "--platform", "linux/arm64", image, "claude --help"],
                           capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stderr)
        for flag in ("--allowedTools", "--disallowedTools", "--permission-mode", "--system-prompt",
                     "--setting-sources", "--effort", "--model"):
            self.assertIn(flag, r.stdout, flag)
        self.assertIn("acceptEdits", r.stdout)


if __name__ == "__main__":
    unittest.main()
