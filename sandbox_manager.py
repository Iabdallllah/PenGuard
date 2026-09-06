import time
import requests
from typing import List

try:
    import docker
    _docker_available = True
except Exception:
    docker = None
    _docker_available = False

class SandboxManager:
    def __init__(self, image_name: str = "purple-target:latest", container_name: str = "purple_sandbox"):
        self.image_name = image_name
        self.container_name = container_name
        self.container = None
        self._client = None
        if _docker_available:
            try:
                self._client = docker.from_env()
            except Exception as e:
                print(f"[sandbox] docker client init failed: {e}")
                self._client = None

    @property
    def client(self):
        if self._client is None and _docker_available:
            try:
                self._client = docker.from_env()
            except Exception:
                pass
        return self._client

    def build_image(self, force: bool = False):
        if not _docker_available or self.client is None:
            print("[sandbox] docker not available, skip build_image")
            return
        if not force:
            try:
                self.client.images.get(self.image_name)
                return
            except Exception:
                # docker.errors.ImageNotFound or client missing
                pass
        try:
            self.client.images.build(
                path=".",
                dockerfile="./sandbox/Dockerfile",
                tag=self.image_name,
                rm=True,
                network_mode="host"
            )
        except Exception as e:
            print(f"[sandbox] build_image failed: {e}")
            raise

    def _wait_for_health(self, host_port: int, timeout: float = 8.0):
        url = f"http://127.0.0.1:{host_port}/"
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = requests.get(url, timeout=1)
                if r.status_code < 500:
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        print(f"[sandbox] health check timeout for {url}")
        return False

    def start_container(self, host_port: int = 8001) -> str:
        if not _docker_available or self.client is None:
            # fallback: assume external target_app or attempt to health-check existing service
            print("[sandbox] docker unavailable, using fallback URL")
            self._wait_for_health(host_port, timeout=2.0)
            return f"http://127.0.0.1:{host_port}"
        self.stop_container()
        try:
            self.container = self.client.containers.run(
                self.image_name,
                name=self.container_name,
                ports={"8000/tcp": host_port},
                detach=True,
                network_mode="bridge"
            )
        except Exception as e:
            print(f"[sandbox] start_container failed: {e}")
            raise
        # wait for service ready rather than fixed sleep
        self._wait_for_health(host_port, timeout=10.0)
        return f"http://127.0.0.1:{host_port}"

    def get_logs(self) -> List[str]:
        if not self.container:
            # try fetch by name if client exists
            if _docker_available and self.client is not None:
                try:
                    c = self.client.containers.get(self.container_name)
                    raw_logs = c.logs(tail=100).decode("utf-8", errors="ignore")
                    return [line for line in raw_logs.split("\n") if line.strip()]
                except Exception:
                    return []
            return []
        try:
            raw_logs = self.container.logs(tail=100).decode("utf-8", errors="ignore")
            return [line for line in raw_logs.split("\n") if line.strip()]
        except Exception as e:
            print(f"[sandbox] get_logs failed: {e}")
            return []

    def reset_state(self, host_port: int = 8001) -> str:
        return self.start_container(host_port=host_port)

    def stop_container(self):
        if not _docker_available or self.client is None:
            return
        try:
            old = self.client.containers.get(self.container_name)
            old.stop()
            old.remove()
            self.container = None
        except Exception:
            # includes docker.errors.NotFound
            pass