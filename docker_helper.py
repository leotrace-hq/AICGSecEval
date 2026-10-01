import docker
import docker.models
import docker.models.containers
import hashlib
import logging
import os
import tarfile
import tempfile
import threading


class DockerHelperImpl:
    _docker_client: docker.DockerClient = None
    _docker_container: docker.models.containers.Container = None

    def __init__(self, trace: str, image: str, command: str, remove_container: bool, privileged: bool):
        self._logger = logging.getLogger()
        self._trace = trace
        self._image = image
        self._remove_container = remove_container
        self._privileged = privileged

        try:
            self._docker_client = docker.from_env()
        except Exception as e:
            raise RuntimeError(f"连接本地 Docker 服务失败：{e}")

        try:
            # The dataset writes image_run_cmd as a SHELL line, e.g.
            #   "/etc/init.d/apache2 start && tail -f /dev/null"
            # docker-py shlex-splits a string command, so "&&" would arrive as a plain argv
            # element: the init script starts Apache, exits 0, and the container dies, after
            # which every exec fails and the status-check log comes back ZERO BYTES. Hand
            # anything with shell syntax to a shell so it means what the dataset intends.
            run_command = command
            if isinstance(command, str) and command.strip() and any(
                    tok in command for tok in ("&&", "||", "|", ";", ">", "<", "$(", "`")):
                run_command = ["sh", "-c", command]

            self._docker_container = self._docker_client.containers.run(
                image=image, command=run_command, stdout=True, stderr=True, remove=True, detach=True,
                privileged=self._privileged,
                # Task images are published for linux/amd64. Some are multi-arch manifest LISTS
                # that simply omit arm64; Docker refuses to start those on an arm64 host rather
                # than emulating, while single-arch amd64 images run under emulation fine. Naming
                # the platform makes both behave the same way, so the benchmark is runnable on
                # Apple Silicon. On an amd64 host this is a no-op.
                platform=os.environ.get("ASE_DOCKER_PLATFORM", "linux/amd64"))
            self._logger.info(
                f"[{self._trace}] 启动镜像 {self._image} 成功，容器：{self._docker_container.name}（{self._docker_container.id}）")
        except Exception as e:
            self.cleanup()
            raise RuntimeError(f"启动镜像 {image} 失败：{e}")

    def execute(self, command: str, timeout: int, output_to_file: str = None, environment: dict = None, workdir: str = None):
        self._logger.info(f"[{self._trace}] 执行命令: {command}")

        caught_exception = None
        exec_id = None
        exec_output = bytearray()

        def execute_command():
            nonlocal caught_exception, exec_id, exec_output

            try:
                exec_id = self._docker_client.api.exec_create(
                    container=self._docker_container.id, cmd=command, environment=environment, workdir=workdir)["Id"]
                exec_stream = self._docker_client.api.exec_start(
                    exec_id=exec_id, stream=True)
            except Exception as e:
                caught_exception = RuntimeError(f"执行命令失败：{e}")
                return

            fp = None
            if output_to_file is not None:
                try:
                    fp = open(output_to_file, "wb")
                except Exception as e:
                    caught_exception = RuntimeError(
                        f"打开文件 {output_to_file} 失败：{e}")
                    return

            try:
                for chunk in exec_stream:
                    exec_output.extend(chunk)
                    if fp is not None:
                        fp.write(chunk)
                        fp.flush()
            except Exception as e:
                caught_exception = RuntimeError(f"读取命令输出失败：{e}")

            if fp is not None:
                fp.close()

        thread = threading.Thread(target=execute_command)
        thread.start()
        thread.join(timeout)

        if caught_exception is not None:
            raise caught_exception

        if thread.is_alive():
            if exec_id is not None:
                self._logger.info(f"[{self._trace}] 执行命令超时：{command}")
                exec_pid = self._docker_client.api.exec_inspect(exec_id)["Pid"]
                self._docker_container.exec_run(f"kill -TERM {exec_pid}")

        return bytes(exec_output)


    def check_file_exists(self, container_path: str):
        exit_code, output = self._docker_container.exec_run(f"test -f {container_path}")
        if exit_code == 0:
            return True
        else:
            self._logger.error(f"[{self._trace}] 检查文件 {container_path} 失败：{output}")
            return False


    def upload(self, host_path: str, container_path: str):
        self._logger.info(
            f"[{self._trace}] 从本地 \"{host_path}\" 复制文件到容器 \"{container_path}\"")

        try:
            with open(host_path, "rb") as f:
                host_md5sum = hashlib.md5(f.read()).hexdigest()

            host_tar_path = f"{host_path}.tar"
            with tarfile.open(host_tar_path, "w") as tar:
                tar.add(host_path, arcname=os.path.basename(container_path))
            with open(host_tar_path, "rb") as f:
                host_tar_data = f.read()
        except Exception as e:
            self._logger.error(
                f"[{self._trace}] 打包本地文件 \"{host_path}\" 失败：{e}")
            return False

        try:
            self._docker_container.put_archive(
                path=os.path.dirname(container_path), data=host_tar_data)
        except Exception as e:
            self._logger.error(f"[{self._trace}] 复制文件到容器失败：{e}")
            return False

        try:
            container_md5sum_result = self.execute(
                command=f"md5sum {container_path}",
                timeout=10,
            )
        except Exception as e:
            self._logger.error(f"[{self._trace}] 获取容器文件 MD5 失败：{e}")
            return False

        if host_md5sum not in container_md5sum_result.decode("utf-8"):
            self._logger.error(f"[{self._trace}] 复制文件到容器失败，MD5 不匹配")
            return False

        return True

    def upload_dir(self, host_path: str, container_path: str):
        self._logger.info(
            f"[{self._trace}] 从本地 \"{host_path}\" 复制目录到容器 \"{container_path}\"")

        with tempfile.TemporaryDirectory() as temp_dir:
            host_tar_path = os.path.join(temp_dir, f"upload.tar")

            try:
                with tarfile.open(host_tar_path, "w") as tar:
                    tar.add(host_path, arcname="")
                with open(host_tar_path, "rb") as f:
                    host_tar_data = f.read()
            except Exception as e:
                self._logger.error(
                    f"[{self._trace}] 打包本地目录 \"{host_path}\" 失败：{e}")
                return False

            # tarfile records the HOST's numeric uid/gid and mode, and put_archive applies them
            # verbatim, so the uploaded tree lands owned by a uid that does not exist in the
            # container (501:20 from a macOS host) with directory modes overwritten too. Anything
            # the application needs to write under its own code directory then fails: OpenEMR
            # cannot create its crypto key and serves a 470-byte warning page with HTTP 200, which
            # the readiness probe reports as the misleading "Attempt failed with status code 200".
            #
            # Restore DIRECTORY ownership and mode, PER PATH, from a snapshot taken before the
            # upload. Not `chown -R` to the top directory's owner: these trees are NOT uniformly
            # owned, and flattening them breaks apps just as thoroughly. snipe-it is the
            # counter-example that proves it: /var/www/html is root:root 755, but bootstrap/cache
            # is abc:users 775 and storage is 777. A recursive chown to root takes Laravel's
            # compiled-view cache away from the web user and the app never comes up (measured:
            # 6 instances, 36 cells, all BROKEN on native amd64 where they had verified fine).
            #
            # Directories only: a directory's ownership and mode are what govern CREATING a file
            # in it, which is what both failures were, and it keeps the snapshot to hundreds of
            # entries rather than tens of thousands.
            #
            # Parsed and reissued from Python rather than as one shell pipeline: exec_create
            # shlex-splits a string command, so a nested find|awk|xargs quoting dance is mangled
            # silently and the restore becomes a no-op that still reports success.
            before = {}
            try:
                # find -exec stat, not find -printf: busybox find (Alpine, and so every
                # LinuxServer-style image here) has no -printf and merely prints its usage,
                # which parses to an empty snapshot and a restore that silently does nothing.
                out = self.execute(
                    command=["find", container_path, "-type", "d",
                             "-exec", "stat", "-c", "%U:%G %a %n", "{}", "+"],
                    timeout=180).decode("utf-8", "replace")
                for line in out.splitlines():
                    parts = line.split(" ", 2)
                    if len(parts) == 3 and ":" in parts[0]:
                        before[parts[2]] = (parts[0], parts[1])
            except Exception as e:
                self._logger.warning(f"[{self._trace}] 记录 {container_path} 目录属主失败，跳过恢复：{e}")

            try:
                self._docker_container.put_archive(path=container_path, data=host_tar_data)
            except Exception as e:
                self._logger.error(f"[{self._trace}] 复制文件到容器失败：{e}")
                return False

            if before:
                groups = {}
                for path, (owner, mode) in before.items():
                    groups.setdefault((owner, mode), []).append(path)
                for (owner, mode), paths in groups.items():
                    for k in range(0, len(paths), 400):   # keep argv well inside its limit
                        chunk = paths[k:k + 400]
                        for cmd in (["chown", "-h", owner, *chunk], ["chmod", mode, *chunk]):
                            try:
                                self.execute(command=cmd, timeout=180)
                            except Exception as e:
                                self._logger.warning(
                                    f"[{self._trace}] 恢复目录属主/权限失败（{owner} {mode}）：{e}")

        return True

    def stop(self):
        if self._docker_container is None:
            return
        try:
            self._logger.info(
                f"[{self._trace}] 停止容器 {self._docker_container.name}")
            self._docker_container.stop()
        except Exception as e:
            self._logger.warning(
                f"[{self._trace}] 停止容器 {self._docker_container.name} 失败，请手动停止，失败原因：{e}")
        try:
            self._logger.info(
                f"[{self._trace}] 等待容器 {self._docker_container.name} 终止")
            self._docker_container.wait(condition="removed")
        except Exception as e:
            self._logger.warning(
                f"[{self._trace}] 等待容器 {self._docker_container.name} 终止失败，失败原因：{e}")
        self._docker_container = None

    def cleanup(self):
        if self._docker_client is None:
            return
        if self._remove_container:
            try:
                self._logger.info(f"[{self._trace}] 删除镜像 {self._image}")
                self._docker_client.images.remove(image=self._image)
            except Exception as e:
                self._logger.warning(
                    f"[{self._trace}] 删除镜像 {self._image} 失败，请手动删除，失败原因：{e}")
        try:
            self._docker_client.close()
        except Exception as e:
            self._logger.warning(
                f"[{self._trace}] 断开与本地 Docker 服务的连接失败，可能会导致资源泄漏，失败原因：{e}")
        self._docker_client = None


class DockerHelper:
    def __init__(self, **kwargs):
        self._instance = DockerHelperImpl(**kwargs)

    def __enter__(self):
        return self._instance

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._instance.stop()
        self._instance.cleanup()
