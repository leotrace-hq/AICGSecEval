import argparse
import os

from bench.agent.base import AgentBenchBase
from bench.agent import _container
from bench.agent import _corridor


# --- LeoBench: the Cursor CLI (LEO-735) ----------------------------------------------
# Container runtime only. The agent step runs in LeoBench's cell container through
# harness/container_agent.py, which drives `cursor-agent` INTERACTIVELY (harness/cursor_tty.py):
# print mode (`cursor-agent -p`) never fires the stop hook LeoPrevent's Cursor plugin reviews
# on, so a leoprevent cycle would run unreviewed (LEO-736). Inside the container it runs with
# --force (the counterpart of Codex's bypass) and web fetch denied, like the Codex cells; on the
# leoprevent arm the staged plugin is installed where a customer installs it,
# ~/.cursor/plugins/local/leoprevent. There is no host runtime: --force on the operator's
# machine would let a prompt injection in a cloned repo run anything there.
# Auth is the Cursor subscription only: a copy of the login made with LeoBench's
# `container_agent.py cursor-login`, per cell.

class CursorAgentBench(AgentBenchBase):
    def __init__(self, logger, repo_dir, agent_args):
        super().__init__(logger, repo_dir, agent_args)
        self._model_name = agent_args.cursor_model
        self._arm = agent_args.arm
        if getattr(agent_args, "agent_runtime", "host") != "container":
            raise ValueError("--agent_name cursor runs with --agent_runtime container only")
        self._corridor_mode = _corridor.resolve_mode(self._arm, agent_args.corridor_mode)
        self._container = _container.ContainerRuntime(
            "cursor", self._arm, self._corridor_mode, repo_dir, self._model_name, logger,
            auth=agent_args.auth, corridor_dist=agent_args.corridor_dist_dir,
            leobench_home=agent_args.leobench_home)

    @staticmethod
    def parse_args(args):
        parser = argparse.ArgumentParser(
            description="Cursor CLI (cursor-agent) for agent evaluation, in LeoBench's container",
            usage="...other_args... --agent --agent_name cursor --agent_runtime container "
                  "[--arm raw|leoprevent] --cursor_model <MODEL>",
            add_help=False
        )
        parser.add_argument("--cursor_model", type=str, default=os.environ.get("CURSOR_MODEL"),
                            help="Cursor model id from `cursor-agent models` (e.g. composer-2.5, "
                                 "grok-4.7-medium); effort is part of the id (default "
                                 "$CURSOR_MODEL)")
        parser.add_argument("--arm", type=str, choices=["raw", "leoprevent", "corridor",
                                                        "commit-control", "sonar-vortex"],
                            default="raw",
                            help="raw = agent alone; leoprevent = agent with the LeoPrevent "
                                 "review plugin (the arms LeoBench's container runtime supports "
                                 "for Cursor are raw and leoprevent)")
        parser.add_argument("--corridor_mode", type=str, choices=list(_corridor.MODES),
                            default=os.environ.get("CORRIDOR_MODE"))
        parser.add_argument("--corridor_dist_dir", type=str,
                            default=os.environ.get("CORRIDOR_DIST_DIR"))
        parser.add_argument("--auth", type=str, choices=["subscription"], default="subscription",
                            help="the Cursor subscription login (LeoBench `container_agent.py "
                                 "cursor-login`)")
        _container.add_args(parser)
        return parser.parse_args(args)

    async def start(self):
        self._container.check()
        self.logger.info(f"Cursor Agent: container runtime (arm={self._arm})")

    async def stop(self):
        pass

    def build_prompt(self, file_path, function_summary, context_file_list):
        return _corridor.with_commit_instruction(
            self.make_prompt(file_path, function_summary, context_file_list),
            self._arm, self._corridor_mode)

    async def generate_code(self, file_path, function_summary, context_file_list):
        prompt = self.build_prompt(file_path, function_summary, context_file_list)
        return self._container.run(prompt, file_path)
