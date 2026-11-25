import argparse
import os
import random
import subprocess
import time
from bench.agent.base import AgentBenchBase
from bench.agent import _container


class GeminiAgentBench(AgentBenchBase):
    def __init__(self, logger, repo_dir, agent_args):
        super().__init__(logger, repo_dir, agent_args)
        self._api_key = agent_args.gemini_api_key
        self._model_name = agent_args.gemini_model
        self._no_sandbox = agent_args.gemini_no_sandbox
        self._container = None
        if agent_args.agent_runtime == "container":
            if agent_args.auth != "vertex":
                raise ValueError("Gemini container cells need --auth vertex")
            self._container = _container.ContainerRuntime(
                "gemini", agent_args.arm, None, repo_dir, self._model_name, logger,
                auth=agent_args.auth, leobench_home=agent_args.leobench_home)

    @staticmethod
    def parse_args(args):
        parser = argparse.ArgumentParser(
            description='配置 Gemini 用于 Agent 评测',
            usage="...other_args... --agent --agent_name gemini " +
                  "[--gemini_api_key <API_KEY> --gemini_model <MODEL> --gemini_no_sandbox]",
            add_help=False
        )
        parser.add_argument("--gemini_api_key", action="append",
                            help="API密钥，如果不提供则从环境变量GEMINI_API_KEY获取，指定多个时每个项目随机选择")
        parser.add_argument("--gemini_model", type=str,
                            default=None, help="模型名称")
        parser.add_argument("--gemini_no_sandbox",
                            default=False, action="store_true", help="是否关闭沙箱")
        parser.add_argument("--arm", choices=("raw", "leoprevent"), default="raw")
        parser.add_argument("--auth", choices=("api-key", "vertex"), default="api-key")
        _container.add_args(parser)
        return parser.parse_args(args)

    async def start(self):
        if self._container is not None:
            self._container.check()

    async def stop(self):
        pass

    async def generate_code(self, file_path, function_summary, context_file_list):
        prompt = self.make_prompt(
            file_path, function_summary, context_file_list)
        if self._container is not None:
            return self._container.run(prompt, file_path)
        self.logger.info(
            f"Gemini is generating code, prompt: {prompt}")

        args = ["gemini", "-d", "--yolo"]

        if self._api_key is not None:
            if isinstance(self._api_key, list):
                os.environ["GEMINI_API_KEY"] = random.choice(self._api_key)
            else:
                os.environ["GEMINI_API_KEY"] = self._api_key
        if not self._no_sandbox:
            os.environ["SANDBOX_SET_UID_GID"] = "true"
            args.append("--sandbox")
        if self._model_name is not None:
            args.extend(["-m", self._model_name])

        args.extend(["-p", prompt])

        self.logger.info(f"Gemini run command: {args[0:-1]} ...prompt...")

        try:
            process = subprocess.Popen(
                args=args,
                cwd=self.repo_dir,
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            os.set_blocking(process.stdout.fileno(), False)
            os.set_blocking(process.stderr.fileno(), False)

            while process.poll() is None:
                while True:
                    stdout = process.stdout.read()
                    if not stdout:
                        break
                    self.logger.info(
                        f"Gemini output: {stdout.decode().strip()}")
                while True:
                    stderr = process.stderr.read()
                    if not stderr:
                        break
                    self.logger.info(
                        f"Gemini output error: {stderr.decode().strip()}")
                time.sleep(0.1)

            exitcode = process.returncode

            self.logger.info(f"Gemini run finish, exitcode: {exitcode}")
            return exitcode == 0

        except Exception as e:
            self.logger.error(f"Gemini run error: {e}")
            return False
