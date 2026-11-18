import argparse
import os

from bench.agent.base import AgentBenchBase
from bench.agent import _container


# --- LeoBench: the Cosine CLI (LEO-987) -----------------------------------------------
# Container runtime only, like Cursor: `cos --auto-accept` on the operator's machine would let a
# prompt injection in a cloned repo run anything there. The agent step runs in LeoBench's cell
# container through harness/container_agent.py, which runs harness/cosine_turn.py (one `cos -p`
# turn, resuming the same session on later calls). On the leoprevent arm the staged plugin's
# `leoprevent exec` drives the loop: run the agent, review the turn's change, resume the session
# with the findings once (cos has no end-of-turn hook; see LeoBench _agents._Cosine).
# Auth is the Cosine subscription login (`cos login`), copied per cell.

class CosineAgentBench(AgentBenchBase):
    def __init__(self, logger, repo_dir, agent_args):
        super().__init__(logger, repo_dir, agent_args)
        self._model_name = agent_args.cosine_model
        self._arm = agent_args.arm
        if getattr(agent_args, "agent_runtime", "host") != "container":
            raise ValueError("--agent_name cosine runs with --agent_runtime container only")
        self._container = _container.ContainerRuntime(
            "cosine", self._arm, None, repo_dir, self._model_name, logger,
            auth=agent_args.auth, leobench_home=agent_args.leobench_home)

    @staticmethod
    def parse_args(args):
        parser = argparse.ArgumentParser(
            description="Cosine CLI (cos) for agent evaluation, in LeoBench's container",
            usage="...other_args... --agent --agent_name cosine --agent_runtime container "
                  "[--arm raw|leoprevent] --cosine_model <MODEL>",
            add_help=False
        )
        parser.add_argument("--cosine_model", type=str, default=os.environ.get("COSINE_MODEL"),
                            help="Cosine model id (e.g. lumen-outpost; default $COSINE_MODEL)")
        parser.add_argument("--arm", type=str, choices=["raw", "leoprevent"], default="raw",
                            help="raw = agent alone; leoprevent = agent with LeoPrevent's "
                                 "end-of-turn review")
        parser.add_argument("--auth", type=str, choices=["subscription"], default="subscription",
                            help="the Cosine subscription login (`cos login`)")
        _container.add_args(parser)
        return parser.parse_args(args)

    async def start(self):
        self._container.check()
        self.logger.info(f"Cosine: container runtime (arm={self._arm})")

    async def stop(self):
        pass

    def build_prompt(self, file_path, function_summary, context_file_list):
        return self.make_prompt(file_path, function_summary, context_file_list)

    async def generate_code(self, file_path, function_summary, context_file_list):
        prompt = self.build_prompt(file_path, function_summary, context_file_list)
        return self._container.run(prompt, file_path)
