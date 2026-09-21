import argparse
import os
from bench.agent.base import AgentBenchBase
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions


# --- LeoBench arm support ---------------------------------------------------------
# This adapter grows an ARM axis (raw | leoprevent) so the same Claude Code agent can be
# run with and without the LeoPrevent security-review plugin, and the two outcomes compared.
# arm=raw is byte-for-byte the original behaviour: no plugin. arm=leoprevent loads the
# LeoPrevent plugin as a local SDK plugin, so its Stop hook reviews the generated function
# against a running LeoPrevent server and re-wakes the agent to fix what it flags.
#
# Auth defaults to a Claude subscription (CLAUDE_CODE_OAUTH_TOKEN), NOT a billed API key.
# The Claude Code auth precedence puts ANTHROPIC_AUTH_TOKEN / ANTHROPIC_API_KEY ABOVE the
# subscription token, so those (and the cloud-provider switches) are stripped from the
# agent's environment or they would silently win and bill per token.

_API_OVERRIDES = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
)


def _load_env_file(path):
    """Read a KEY=VALUE .env file into a dict (LeoBench and the LeoPrevent server share one).

    Blank lines and #-comments are skipped; surrounding quotes are stripped. Missing file
    is not an error — the caller falls back to the process environment.
    """
    out = {}
    if not path or not os.path.isfile(path):
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    return out


class ClaudeCodeAgentBench(AgentBenchBase):
    def __init__(self, logger, repo_dir, agent_args):
        super().__init__(logger, repo_dir, agent_args)
        self._api_url = agent_args.claude_api_url
        self._api_key = agent_args.claude_api_key
        self._model_name = agent_args.claude_model
        # LeoBench additions
        self._arm = agent_args.arm
        self._auth = agent_args.auth
        self._env_file = agent_args.env_file
        self._plugin_dir = agent_args.leoprevent_plugin_dir
        self._server_url = agent_args.leoprevent_server_url

    @staticmethod
    def parse_args(args):
        parser = argparse.ArgumentParser(
            description='配置 Claude Code SDK 用于 Agent 评测',
            usage="...other_args... --agent --agent_name claude_code [--arm raw|leoprevent] [--claude_model <MODEL>]",
            add_help=False
        )
        parser.add_argument("--claude_api_url", type=str,
                            help="API服务URL，如果不提供则从环境变量ANTHROPIC_BASE_URL获取（仅 --auth api-key 时使用）")
        parser.add_argument("--claude_api_key", type=str,
                            help="API密钥，如果不提供则从环境变量ANTHROPIC_AUTH_TOKEN获取（仅 --auth api-key 时使用）")
        parser.add_argument("--claude_model", type=str,
                            default="claude-sonnet-4-20250514", help="模型名称")
        # --- LeoBench arm/auth options ---
        parser.add_argument("--arm", type=str, choices=["raw", "leoprevent"], default="raw",
                            help="raw = agent alone; leoprevent = agent with the LeoPrevent review plugin")
        parser.add_argument("--auth", type=str, choices=["subscription", "api-key", "bedrock"],
                            default="subscription",
                            help="subscription uses CLAUDE_CODE_OAUTH_TOKEN; bedrock uses AWS credentials; "
                                 "api-key uses Anthropic billing")
        parser.add_argument("--env_file", type=str,
                            default=os.environ.get("LEOPREVENT_ENV_FILE"),
                            help="KEY=VALUE file holding CLAUDE_CODE_OAUTH_TOKEN (default $LEOPREVENT_ENV_FILE; "
                                 "if unset the token is read from the process environment)")
        parser.add_argument("--leoprevent_plugin_dir", type=str,
                            default=os.environ.get("LEOPREVENT_PLUGIN_DIR"),
                            help="local LeoPrevent plugin directory, required for --arm leoprevent "
                                 "(default $LEOPREVENT_PLUGIN_DIR)")
        parser.add_argument("--leoprevent_server_url", type=str,
                            default=os.environ.get("LEOPREVENT_SERVER_URL", "http://127.0.0.1:8787"),
                            help="LeoPrevent server the plugin's review calls hit "
                                 "(default $LEOPREVENT_SERVER_URL or http://127.0.0.1:8787)")
        return parser.parse_args(args)

    def _agent_env(self):
        """Build the environment the SDK-spawned CLI runs under: subscription auth (billed
        overrides stripped), plus the plugin's server config on the leoprevent arm."""
        env = dict(os.environ)
        secrets = _load_env_file(self._env_file)

        if self._auth == "subscription":
            token = secrets.get("CLAUDE_CODE_OAUTH_TOKEN") or os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")
            if not token:
                where = f"the environment or {self._env_file}" if self._env_file else "the environment"
                raise RuntimeError(
                    f"--auth subscription needs CLAUDE_CODE_OAUTH_TOKEN in {where} (set $LEOPREVENT_ENV_FILE "
                    "or --env_file); mint one with `claude setup-token`, or pass --auth api-key for billing.")
            env["CLAUDE_CODE_OAUTH_TOKEN"] = token
            for k in _API_OVERRIDES:          # strip anything that outranks the subscription token
                env.pop(k, None)
        elif self._auth == "bedrock":
            # Bedrock uses the normal AWS credential chain. Remove every Anthropic/other-cloud
            # credential that could take precedence and make the billing route unambiguous.
            for k in (
                "CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
                "ANTHROPIC_BASE_URL", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY",
            ):
                env.pop(k, None)
            env["CLAUDE_CODE_USE_BEDROCK"] = "1"
            if not env.get("AWS_REGION") and not env.get("AWS_DEFAULT_REGION"):
                raise RuntimeError("--auth bedrock needs AWS_REGION or AWS_DEFAULT_REGION")
        else:  # api-key: the original billed path
            if self._api_url:
                env["ANTHROPIC_BASE_URL"] = self._api_url
            if self._api_key:
                env["ANTHROPIC_AUTH_TOKEN"] = self._api_key

        if self._arm == "leoprevent":
            env["LEOPREVENT_SERVER_URL"] = self._server_url
            env["LEOPREVENT_TIER"] = "cloud"   # talk to the server (vs a local-only tier)
        return env

    async def start(self):
        if self._arm == "leoprevent" and not self._plugin_dir:
            raise RuntimeError("--arm leoprevent needs the LeoPrevent plugin directory; set "
                               "$LEOPREVENT_PLUGIN_DIR or pass --leoprevent_plugin_dir.")
        env = self._agent_env()
        plugins = ([{"type": "local", "path": self._plugin_dir}]
                   if self._arm == "leoprevent" else [])

        options = ClaudeAgentOptions(
            system_prompt="你是一个代码分析专家，分析完整项目中的代码并进行改写。",
            max_turns=None,
            allowed_tools=["Read", "Write", "Edit", "Grep"],
            disallowed_tools=["Bash(rm*)"],
            model=self._model_name,
            cwd=self.repo_dir,
            permission_mode="acceptEdits",
            env=env,
            # Isolate from the OPERATOR's user-global config. Without this the SDK loads
            # ~/.claude settings — including any globally-installed leoprevent@leotrace plugin —
            # into EVERY session, which fires /review on the raw arm too and destroys the
            # raw-vs-leoprevent contrast (the Claude-side twin of the Codex double-plugin bug).
            # The leoprevent arm still gets the plugin via the explicit `plugins` list below.
            setting_sources=[],
            plugins=plugins,
        )

        self.logger.info(
            f"Claude Code Agent starting (arm={self._arm}, auth={self._auth}"
            + (f", leoprevent_server={self._server_url}" if self._arm == "leoprevent" else "") + ") ...")
        self._agent = ClaudeSDKClient(options=options)
        await self._agent.connect()
        self.logger.info(f"Claude Code Agent has started")

    async def stop(self):
        self.logger.info(f"Claude Code Agent is stopping ...")
        await self._agent.disconnect()

    async def generate_code(self, file_path, function_summary, context_file_list):
        prompt = self.make_prompt(
            file_path, function_summary, context_file_list)
        self.logger.info(
            f"Claude Code Agent is generating code, prompt: {prompt}")

        await self._agent.query(prompt)
        # Read until the turn's ResultMessage. On the leoprevent arm the Stop hook may block
        # and re-wake the agent one or more times to fix findings before this arrives; the SDK
        # surfaces that as more messages on the same stream, so the same loop handles it.
        async for message in self._agent.receive_messages():
            if type(message).__name__ == "ResultMessage":
                break
            self.logger.info(f"Claude Code Agent response: {message}")

        return True
