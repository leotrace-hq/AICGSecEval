import argparse
import os
import shutil
import subprocess
import tempfile
import time
from bench.agent.base import AgentBenchBase
from bench.agent import _leobench


# --- LeoBench arm support (see bench/agent/claude_code.py for the rationale) ------
# arm=raw is the original behaviour. arm=leoprevent installs the LeoPrevent plugin into a
# throwaway CODEX_HOME (via a local marketplace) so its Stop hook reviews the regenerated
# function against a running LeoPrevent server and re-wakes Codex to fix findings.
# Auth defaults to a ChatGPT subscription (~/.codex/auth.json, auth_mode=chatgpt), not a
# billed OpenAI key. The operator's own leoprevent registration is stripped from the staged
# config so it does not load a second time (the double-review bug).

class CodexAgentBench(AgentBenchBase):
    def __init__(self, logger, repo_dir, agent_args):
        super().__init__(logger, repo_dir, agent_args)
        self._api_url = agent_args.codex_api_url
        self._api_key = agent_args.codex_api_key
        self._wire_api = agent_args.codex_wire_api
        self._model_name = agent_args.codex_model
        self._sandbox_mode = agent_args.codex_sandbox_mode
        # LeoBench additions
        self._arm = agent_args.arm
        self._auth = agent_args.auth
        self._plugin_dir = agent_args.leoprevent_plugin_dir
        self._server_url = agent_args.leoprevent_server_url
        self._stage = None
        self._env = None

    @staticmethod
    def parse_args(args):
        parser = argparse.ArgumentParser(
            description='配置 Codex 用于 Agent 评测',
            usage="...other_args... --agent --agent_name codex [--arm raw|leoprevent] [--codex_model <MODEL>]",
            add_help=False
        )
        parser.add_argument("--codex_api_url", type=str, default=None, help="API服务URL（仅 --auth api-key）")
        parser.add_argument("--codex_api_key", type=str, help="API密钥，如果不提供则从环境变量OPENAI_API_KEY获取（仅 --auth api-key）")
        parser.add_argument("--codex_wire_api", type=str, default="chat", help="API接口")
        parser.add_argument("--codex_model", type=str, default=None, help="模型名称")
        parser.add_argument("--codex_sandbox_mode", type=str, default="workspace-write", help="沙箱模式（保留兼容，leobench 臂统一使用 bypass）")
        # --- LeoBench arm/auth options ---
        parser.add_argument("--arm", type=str, choices=["raw", "leoprevent"], default="raw",
                            help="raw = agent alone; leoprevent = agent with the LeoPrevent review plugin")
        parser.add_argument("--auth", type=str, choices=["subscription", "api-key"], default="subscription",
                            help="subscription uses ~/.codex/auth.json (ChatGPT); refuses to fall back to a billed OpenAI key")
        parser.add_argument("--env_file", type=str,
                            default=os.environ.get("LEOPREVENT_ENV_FILE",
                                                   "/Users/bbaukema/Documents/github/leotrace-hq/leoprevent/server/.env"))
        parser.add_argument("--leoprevent_plugin_dir", type=str,
                            default=os.environ.get("LEOPREVENT_PLUGIN_DIR",
                                                   "/Users/bbaukema/Documents/github/leotrace-hq/leoprevent/plugin"))
        parser.add_argument("--leoprevent_server_url", type=str,
                            default=os.environ.get("LEOPREVENT_SERVER_URL", "http://127.0.0.1:8787"))
        return parser.parse_args(args)

    async def start(self):
        env = dict(os.environ)
        self._stage = tempfile.mkdtemp(prefix="asecodex-")

        if self._auth == "subscription":
            host_codex = os.path.expanduser("~/.codex")
            auth = os.path.join(host_codex, "auth.json")
            if not os.path.isfile(auth):
                raise RuntimeError("--auth subscription needs ~/.codex/auth.json; run `codex login` "
                                   "with ChatGPT, or pass --auth api-key to accept OpenAI billing.")
            env.pop("OPENAI_API_KEY", None)
            env["CODEX_HOME"] = _leobench.stage_codex_home(host_codex, self._stage)
        else:
            if self._api_key:
                env["OPENAI_API_KEY"] = self._api_key

        if self._arm == "leoprevent":
            env["LEOPREVENT_SERVER_URL"] = self._server_url
            env["LEOPREVENT_TIER"] = "cloud"
            mkt = _leobench.stage_codex_marketplace(self._plugin_dir, self._stage)
            for cmd in (["codex", "plugin", "marketplace", "add", mkt],
                        ["codex", "plugin", "add", "leoprevent@leotrace-local"]):
                r = subprocess.run(cmd, env=env, capture_output=True, text=True)
                if r.returncode != 0:
                    raise RuntimeError(f"codex plugin setup failed ({' '.join(cmd[:3])}...):\n{r.stderr[-400:]}")
            self.logger.info(f"Codex leoprevent plugin installed; server={self._server_url}")

        self._env = env
        self.logger.info(f"Codex Agent ready (arm={self._arm}, auth={self._auth})")

    async def stop(self):
        if self._stage:
            shutil.rmtree(self._stage, ignore_errors=True)

    def _argv(self, prompt):
        cmd = ["codex", "exec", prompt]
        if self._model_name:
            cmd += ["-m", self._model_name]
        if self._api_url and self._auth == "api-key":
            cmd += ["-c", 'model_providers.codex.name="codex"',
                    "-c", f'model_providers.codex.base_url="{self._api_url}"',
                    "-c", f'model_providers.codex.wire_api="{self._wire_api}"',
                    "-c", 'model_providers.codex.env_key="OPENAI_API_KEY"',
                    "-c", 'model_provider="codex"']
        # Headless BUT sandboxed. This runs on the host (not a container like LeoBench), and the
        # prompt carries content derived from cloned benchmark repos and dataset function
        # summaries — untrusted, prompt-injectable input. A full approvals/sandbox bypass would
        # let an injection run arbitrary commands on the developer's machine with the host
        # ChatGPT credentials. So confine writes to the workspace and never bypass the sandbox:
        # workspace-write + approval 'never' completes headlessly without host command execution.
        # --approve-for-me is headless auto-approval that runs commands inside the workspace-write
        # sandbox (it implies the sandbox, so --sandbox must not also be passed). Writes stay in
        # the workspace; there is no arbitrary host command execution.
        cmd += ["--approve-for-me", "--skip-git-repo-check"]
        if self._arm == "leoprevent":
            # The plugin's Stop hook posts the diff to the review server, so the workspace-write
            # sandbox must permit outbound network for that one call; hooks still need trust
            # bypassed to fire headlessly. Neither widens filesystem access beyond the workspace.
            cmd += ["-c", "sandbox_workspace_write.network_access=true",
                    "--dangerously-bypass-hook-trust"]
        return cmd

    async def generate_code(self, file_path, function_summary, context_file_list):
        prompt = self.make_prompt(file_path, function_summary, context_file_list)
        args = self._argv(prompt)
        self.logger.info(f"Codex run command: {args[:2]} ...prompt... {args[3:]}")

        try:
            process = subprocess.Popen(args=args, cwd=self.repo_dir, stdin=None,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self._env)
            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stderr.fileno(), False)
            while process.poll() is None:
                while True:
                    out = process.stdout.read()
                    if not out:
                        break
                    self.logger.info(f"Codex output: {out.decode(errors='replace').strip()}")
                while True:
                    err = process.stderr.read()
                    if not err:
                        break
                    self.logger.info(f"Codex output error: {err.decode(errors='replace').strip()}")
                time.sleep(0.1)
            self.logger.info(f"Codex run finish, exitcode: {process.returncode}")
            return process.returncode == 0
        except Exception as e:
            self.logger.error(f"Codex run error: {e}")
            return False
