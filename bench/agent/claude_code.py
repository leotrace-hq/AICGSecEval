import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from bench.agent.base import AgentBenchBase
from bench.agent import _corridor
from claude_agent_sdk import ClaudeSDKClient, ClaudeAgentOptions


# --- LeoBench arm support ---------------------------------------------------------
# This adapter grows an ARM axis (raw | leoprevent) so the same Claude Code agent can be
# run with and without the LeoPrevent security-review plugin, and the two outcomes compared.
# arm=raw is byte-for-byte the original behaviour: no plugin. arm=leoprevent loads the
# LeoPrevent plugin as a local SDK plugin, so its Stop hook reviews the generated function
# against a running LeoPrevent server and re-wakes the agent to fix what it flags.
# arm=security-guidance loads Anthropic's own security-guidance plugin (claude-plugins-official)
# the same way: its Stop hook sends the turn's diff to an Opus review and re-wakes the agent
# with any high/critical findings. See the SG_* helpers at the bottom of this file.
# arm=corridor runs Corridor in one of two modes (--corridor_mode long-running | developer) and
# arm=commit-control is raw plus the commit sentence; both live in bench/agent/_corridor.py.
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
        self._sg_plugin_dir = agent_args.sg_plugin_dir
        # The plugin's per-cycle state dir (its session state and log.txt) sits BESIDE the
        # cycle's code dir, never inside it: the cycle dir is what A.S.E scans and ships to
        # the verification image, so nothing of the tool may land there.
        cycle = Path(repo_dir)
        self._sg_state = cycle.parent / "_security" / cycle.name
        self._corridor_mode = None
        self._corridor = None
        self._collector = None
        if self._arm in _corridor.ARMS:
            self._corridor_mode = _corridor.resolve_mode(self._arm, agent_args.corridor_mode)
            self._corridor = _corridor.CorridorCell(self._arm, self._corridor_mode, "claude", repo_dir,
                                                    agent_args.corridor_dist_dir, logger)

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
        parser.add_argument("--arm", type=str,
                            choices=["raw", "leoprevent", "security-guidance", "corridor", "commit-control"],
                            default="raw",
                            help="raw = agent alone; leoprevent = agent with the LeoPrevent review plugin; "
                                 "security-guidance = agent with Anthropic's security-guidance plugin; "
                                 "corridor = agent with Corridor (--corridor_mode); "
                                 "commit-control = raw plus the commit sentence")
        parser.add_argument("--corridor_mode", type=str, choices=list(_corridor.MODES),
                            default=os.environ.get("CORRIDOR_MODE"),
                            help="Corridor setup for --arm corridor (default $CORRIDOR_MODE)")
        parser.add_argument("--corridor_dist_dir", type=str,
                            default=os.environ.get("CORRIDOR_DIST_DIR"),
                            help="staged Corridor distribution for --arm corridor (default "
                                 "$CORRIDOR_DIST_DIR); the key comes from $CORRIDOR_API_KEY only")
        parser.add_argument("--sg_plugin_dir", type=str,
                            default=os.environ.get("SECURITY_GUIDANCE_PLUGIN_DIR"),
                            help="security-guidance plugin directory, required for --arm "
                                 "security-guidance (default $SECURITY_GUIDANCE_PLUGIN_DIR). Point it "
                                 "at a run-level snapshot, not the auto-updating marketplace copy.")
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
        # Effort is the model's own default unless a run chooses one: an effort override in the
        # launching shell must not reach the agent unnoticed (setting_sources=[] already keeps
        # the operator's settings.json, and its effortLevel, out).
        env.pop("CLAUDE_CODE_EFFORT_LEVEL", None)
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
        if self._arm == "security-guidance":
            env["SECURITY_WARNINGS_STATE_DIR"] = str(self._sg_state)
            # The plugin's review reads ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN from its hook's
            # environment, and on a subscription Claude Code passes it neither (measured
            # 2026-10-06, LeoBench run_cell.py has the detail): without this the review skips
            # with "no API credentials". The SAME subscription token is handed over as
            # ANTHROPIC_AUTH_TOKEN, so nothing is billed per token; the agent then authenticates
            # through that variable instead of CLAUDE_CODE_OAUTH_TOKEN, same token, same account.
            if self._auth == "subscription":
                env["ANTHROPIC_AUTH_TOKEN"] = env["CLAUDE_CODE_OAUTH_TOKEN"]
        # No agent ever needs the Corridor key (the install step gets it, the agent does not).
        env.pop(_corridor.API_KEY_ENV, None)
        if self._corridor is not None:
            self._corridor.apply_agent_env(env)
        return env

    async def start(self):
        if self._arm == "leoprevent" and not self._plugin_dir:
            raise RuntimeError("--arm leoprevent needs the LeoPrevent plugin directory; set "
                               "$LEOPREVENT_PLUGIN_DIR or pass --leoprevent_plugin_dir.")
        if self._arm == "security-guidance":
            if not (self._sg_plugin_dir and os.path.isfile(
                    os.path.join(self._sg_plugin_dir, ".claude-plugin", "plugin.json"))):
                raise RuntimeError("--arm security-guidance needs the plugin directory; set "
                                   "$SECURITY_GUIDANCE_PLUGIN_DIR or pass --sg_plugin_dir.")
            # A fresh state dir per cycle, so one cycle's log and session state never count
            # for another (a re-run of the cycle starts clean too).
            if self._sg_state.exists():
                import shutil
                shutil.rmtree(self._sg_state)
            self._sg_state.mkdir(parents=True)
            # The cycle dir is a fresh copytree, so every git index entry has stale stat data
            # and the plugin's turn-start `git stash create` (15s limit) would refresh the whole
            # index first. On a large repo that can time out, the plugin then diffs against
            # HEAD, and HEAD still holds the function A.S.E masked: the reviewer would see the
            # original. Refreshing here, content-neutral, makes the stash fast; sg_classify's
            # baseline_fallback still catches a cycle where it fails anyway.
            import subprocess
            subprocess.run(["git", "update-index", "-q", "--refresh"], cwd=self.repo_dir,
                           capture_output=True, timeout=900)
        extra = {}
        if self._corridor is not None:
            # Install and verify before the agent starts; a failure raises (cycle failed, the
            # record says installed=false), never a silent raw cell.
            self._corridor.prepare()
            self._collector = _corridor.ClaudeEventCollector()
            extra = self._corridor.claude_options()
        env = self._agent_env()
        plugins = ([{"type": "local", "path": self._plugin_dir}] if self._arm == "leoprevent"
                   else [{"type": "local", "path": self._sg_plugin_dir}]
                   if self._arm == "security-guidance" else extra.pop("plugins", []))
        allowed_tools = ["Read", "Write", "Edit", "Grep"] + extra.pop("extra_allowed_tools", [])
        setting_sources = extra.pop("setting_sources", [])

        options = ClaudeAgentOptions(
            system_prompt="你是一个代码分析专家，分析完整项目中的代码并进行改写。",
            max_turns=None,
            allowed_tools=allowed_tools,
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
            # (corridor, both modes: ["user"] from the cell's own HOME, which holds only what
            # Corridor installed: its plugin in developer mode, its Claude Code hooks in
            # long-running mode. No explicit plugin: Corridor registers its own.)
            setting_sources=setting_sources,
            plugins=plugins,
            **extra,
        )

        self.logger.info(
            f"Claude Code Agent starting (arm={self._arm}, auth={self._auth}"
            + (f", leoprevent_server={self._server_url}" if self._arm == "leoprevent" else "")
            + (f", corridor_mode={self._corridor_mode}" if self._corridor_mode else "") + ") ...")
        self._agent = ClaudeSDKClient(options=options)
        await self._agent.connect()
        self.logger.info(f"Claude Code Agent has started")

    async def stop(self):
        self.logger.info(f"Claude Code Agent is stopping ...")
        await self._agent.disconnect()

    def build_prompt(self, file_path, function_summary, context_file_list):
        return _corridor.with_commit_instruction(
            self.make_prompt(file_path, function_summary, context_file_list),
            self._arm, self._corridor_mode)

    async def generate_code(self, file_path, function_summary, context_file_list):
        prompt = self.build_prompt(
            file_path, function_summary, context_file_list)
        self.logger.info(
            f"Claude Code Agent is generating code, prompt: {prompt}")

        await self._agent.query(prompt)
        # Read until the turn's ResultMessage. On the leoprevent arm the Stop hook may block
        # and re-wake the agent one or more times to fix findings before this arrives; the SDK
        # surfaces that as more messages on the same stream, so the same loop handles it.
        #
        # security-guidance is different: its Stop hook is asyncRewake, so the review runs
        # AFTER the ResultMessage and a re-wake arrives as a whole second turn with its own
        # ResultMessage (measured 2026-10-06: result at 17s, fix turn's result at 30s).
        # Stopping at the first one would discard the fix, so on that arm each ResultMessage
        # is followed by waiting for the plugin's verdict on that Stop: findings mean another
        # turn is coming and is read too; any other verdict ends the cycle.
        sg_log = self._sg_state / "log.txt"
        cursor = 0
        stream = self._agent.receive_messages()

        collector = self._collector

        async def read_turn():
            async for message in stream:
                if collector is not None:
                    collector.feed(message)
                if type(message).__name__ == "ResultMessage":
                    return
                self.logger.info(f"Claude Code Agent response: {message}")

        if self._corridor is not None:
            try:
                await read_turn()
                if self._arm == "corridor" and self._corridor_mode == "developer" and _corridor.DEV_WAIT_REWAKE:
                    await _corridor_follow_rewakes(stream, collector, self._corridor, self.logger)
            finally:
                if collector.init:
                    self.logger.info(f"Corridor cell session init: {collector.init}")
                review = self._corridor.finish(collector.events, file_path)
                self.logger.info(f"{self._arm} record: {review.get('reason') or review}")
            return True

        await read_turn()
        while self._arm == "security-guidance":
            verdict, cursor = await _sg_wait_stop_verdict(sg_log, cursor)
            self.logger.info(f"security-guidance Stop verdict: {verdict}")
            if verdict != "findings":
                break
            # The plugin promised a re-wake. Bounded, so a re-wake that never arrives ends
            # the cycle with what was written instead of hanging the whole batch.
            try:
                await asyncio.wait_for(read_turn(), timeout=SG_REWAKE_TURN_TIMEOUT_S)
            except asyncio.TimeoutError:
                self.logger.error("security-guidance re-wake turn did not finish in "
                                  f"{SG_REWAKE_TURN_TIMEOUT_S}s; ending the cycle")
                break

        if self._arm == "security-guidance":
            review = sg_classify(sg_log)
            (self._sg_state / "sg_review.json").write_text(json.dumps(review, indent=2))
            self.logger.info(f"security-guidance review: {review['signal']}")
        return True


# --- corridor arm: developer-mode re-wake wait -------------------------------------------

async def _corridor_follow_rewakes(stream, collector, cell, logger):
    """After a turn's ResultMessage, keep reading while Corridor's Stop hook re-wakes the agent.

    PILOT: whether Corridor's Stop hook is synchronous (the SDK then continues the same turn and
    this returns after one empty wait) or asyncRewake (like security-guidance: a second turn with
    its own ResultMessage). Sg-style poll with a timeout: wait up to DEV_STOP_WAIT_S for either the
    next message (a re-wake turn, read to its ResultMessage) or a clean Stop line in the cell's
    Corridor log (DEV_STOP_CLEAN_RE); either a clean line or the timeout ends the cycle."""
    while True:
        log_cursor = len(cell.corridor_logs())
        nxt = asyncio.ensure_future(stream.__anext__())
        deadline = time.monotonic() + _corridor.DEV_STOP_WAIT_S
        ended = None
        while time.monotonic() < deadline and not nxt.done():
            if _corridor.DEV_STOP_CLEAN_RE.search(cell.corridor_logs()[log_cursor:]):
                ended = "clean Stop line in the Corridor log"
                break
            await asyncio.wait([nxt], timeout=2.0)
        if not nxt.done():
            nxt.cancel()
            logger.info(f"Corridor: no re-wake ({ended or f'{_corridor.DEV_STOP_WAIT_S}s wait'}); cycle ends")
            return
        try:
            message = nxt.result()
        except StopAsyncIteration:
            return
        collector.feed(message)
        logger.info(f"Corridor re-wake: {message}")
        if type(message).__name__ == "ResultMessage":
            continue

        async def rest_of_turn():
            async for m in stream:
                collector.feed(m)
                if type(m).__name__ == "ResultMessage":
                    return
                logger.info(f"Claude Code Agent response: {m}")
        try:
            await asyncio.wait_for(rest_of_turn(), timeout=_corridor.DEV_REWAKE_TURN_TIMEOUT_S)
        except asyncio.TimeoutError:
            logger.error("Corridor re-wake turn did not finish in time; ending the cycle")
            return


# --- security-guidance arm helpers --------------------------------------------------
# These read the plugin's own debug log (v2.0.9 wording, security_reminder_hook.py), never
# paraphrase it. They mirror LeoBench's harness/run_cell.py classify_security_guidance, plus
# one A.S.E-specific check, the baseline fallback (see sg_classify).

# The re-wake (fix) turn gets the same order of time as a whole cycle.
SG_REWAKE_TURN_TIMEOUT_S = 1800

# The line that closes one Stop fire, and what it means.
_SG_STOP_VERDICTS = (
    ("Updated git baseline after stop hook", "findings"),     # findings sent, re-wake coming
    ("Stop hook: no security issues found", "clean"),
    ("Stop hook: API call failed", "api-failed"),
)
# Stop-hook progress lines, which do NOT close a fire. Any other "Stop hook: " line is a skip.
_SG_STOP_PROGRESS = ("Stop hook: review_set=", "Stop hook: reviewing ", "Stop hook: repo resolved",
                     "Stop hook: prioritized to", "Stop hook: diff against",
                     "Stop hook: LLM reviews took")
# A Stop review that diffed against HEAD instead of the turn-start snapshot. A.S.E's masked
# function is an UNCOMMITTED edit, so a HEAD diff shows the reviewer the original upstream
# function, and its findings can quote it back to the agent: a ground-truth leak.
_SG_BASELINE_FALLBACK = ("Failed to capture git baseline", "No commits in repo",
                         "falling back to", "not a git repo")


def _sg_messages(log_path):
    try:
        text = Path(log_path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [l.split("] ", 1)[1] if l.startswith("[") and "] " in l else l
            for l in text.splitlines()]


async def _sg_wait_stop_verdict(log_path, cursor, timeout=600, poll=2.0):
    """Wait for the next Stop fire's closing line after message index `cursor`.

    Returns (verdict, new_cursor). verdict is "findings", "clean", "api-failed", "skipped",
    or "timeout" when the plugin never closed the fire (the cycle then ends as it would
    have without this arm, and sg_classify reports what the log does say)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msgs = _sg_messages(log_path)
        for i in range(cursor, len(msgs)):
            m = msgs[i]
            for needle, verdict in _SG_STOP_VERDICTS:
                if m.startswith(needle):
                    return verdict, i + 1
            if m.startswith("Stop hook: ") and not m.startswith(_SG_STOP_PROGRESS):
                return "skipped", i + 1
        await asyncio.sleep(poll)
    return "timeout", cursor


def sg_classify(log_path):
    """Was this cycle reviewed, did findings reach the agent, and is it leak-free?

    reviewed       at least one Stop fire got a verdict from the model
    findings_fires fires whose findings were sent back to the agent (each re-wakes it)
    baseline_fallback  a Stop review may have diffed against HEAD; the cycle must be
                   EXCLUDED from analysis, because the reviewer saw the masked original
    """
    msgs = _sg_messages(log_path)
    out = {"reviewed": False, "signal": None, "reason": None, "reviews": 0,
           "findings_fires": 0, "baseline_fallback": False}
    if not msgs:
        out.update(signal="no log.txt", reason="hook never ran")
        return out
    last_skip = None
    for m in msgs:
        if any(n in m for n in _SG_BASELINE_FALLBACK):
            out["baseline_fallback"] = True
        if m.startswith("Updated git baseline after stop hook"):
            out["reviews"] += 1
            out["findings_fires"] += 1
        elif m.startswith("Stop hook: no security issues found"):
            out["reviews"] += 1
        elif m.startswith("Stop hook: ") and not m.startswith(_SG_STOP_PROGRESS):
            last_skip = m
    out["reviewed"] = out["reviews"] > 0
    if out["reviewed"]:
        out["signal"] = f"{out['reviews']} review(s), {out['findings_fires']} with findings"
    else:
        out["signal"] = last_skip or "no Stop review in log.txt"
        out["reason"] = (last_skip or "hook ran but never reached a review").split(": ", 1)[-1]
    return out
