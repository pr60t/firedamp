"""
Target orchestration and lifecycle management for Firedamp.
Handles spinning up ephemeral Docker containers or attaching to remote instances.
"""

from __future__ import annotations

import logging
import socket
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, TYPE_CHECKING
import urllib.request
import urllib.error

if TYPE_CHECKING:
    import docker
    from docker.models.containers import Container
    from docker.models.images import Image

logger = logging.getLogger("firedamp.target")

# Optional import of docker SDK for graceful error messaging when not installed
try:
    import docker
    from docker.errors import DockerException, NotFound, APIError
except ImportError:
    docker = None  # type: ignore
    DockerException = Exception  # type: ignore
    NotFound = Exception  # type: ignore
    APIError = Exception  # type: ignore


@dataclass
class TargetEnvironment:
    """Represents a running target deployment for isolation testing."""
    name: str
    base_url: str
    host: str = "localhost"
    port: int = 8080
    container_id: Optional[str] = None
    managed_by_docker: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def api_url(self) -> str:
        return self.base_url.rstrip("/")


class BaseTargetManager(ABC):
    """Abstract interface for managing target RAG system lifecycles."""

    @abstractmethod
    def start(self, version: str = "latest", timeout: int = 60) -> TargetEnvironment:
        """Provision or connect to the target environment."""
        pass

    @abstractmethod
    def is_healthy(self, env: TargetEnvironment) -> bool:
        """Verify the target system is responding and ready for testing."""
        pass

    @abstractmethod
    def stop(self, env: TargetEnvironment) -> None:
        """Tear down or disconnect from the target environment."""
        pass


class RemoteTargetManager(BaseTargetManager):
    """Connects to an existing remote or pre-provisioned RAG deployment."""

    def __init__(self, target_url: str, target_name: str = "remote"):
        self.target_url = target_url.rstrip("/")
        self.target_name = target_name

    def start(self, version: str = "latest", timeout: int = 30) -> TargetEnvironment:
        env = TargetEnvironment(
            name=self.target_name,
            base_url=self.target_url,
            managed_by_docker=False
        )
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.is_healthy(env):
                logger.info(f"Connected to remote target at {self.target_url}")
                return env
            time.sleep(2)
        raise TimeoutError(f"Target at {self.target_url} failed health check within {timeout}s.")

    def is_healthy(self, env: TargetEnvironment) -> bool:
        try:
            req = urllib.request.Request(
                f"{env.base_url}/health",
                headers={"User-Agent": "Firedamp-HealthCheck/0.1.0"}
            )
            with urllib.request.urlopen(req, timeout=3) as resp:
                return resp.status in (200, 204, 301, 302)
        except urllib.error.HTTPError as e:
            # Many APIs return 401 or 404 on /health if unauthenticated, meaning server is reachable
            return e.code in (200, 401, 403, 404)
        except Exception:
            # Fallback check on root URL
            try:
                with urllib.request.urlopen(env.base_url, timeout=3) as resp:
                    return resp.status in (200, 301, 302)
            except Exception:
                return False

    def stop(self, env: TargetEnvironment) -> None:
        logger.info(f"Detached from remote target {env.base_url}")


class OpenWebUIContainerManager(BaseTargetManager):
    """
    Manages Open WebUI container lifecycles via the official Docker Python SDK.
    Provides methods to:
      1. Check if an Open WebUI container is currently running.
      2. Pull a specific image version tag from the registry.
      3. Cleanly stop and tear down containers with volume/network cleanup.
    """

    DEFAULT_IMAGE_REPO = "ghcr.io/open-webui/open-webui"
    DEFAULT_CONTAINER_PREFIX = "firedamp-openwebui"

    def __init__(
        self,
        image_repo: str = DEFAULT_IMAGE_REPO,
        client: Optional["docker.DockerClient"] = None,
    ):
        self.image_repo = image_repo
        self._client = client
        self._active_container: Optional["Container"] = None

    @property
    def client(self) -> "docker.DockerClient":
        """Lazily initialize and return the Docker SDK client."""
        if self._client is not None:
            return self._client

        if docker is None:
            raise ImportError(
                "The 'docker' SDK is required for OpenWebUIContainerManager. "
                "Please install it with: pip install docker"
            )

        try:
            self._client = docker.from_env()
            # Ping daemon to verify connection
            self._client.ping()
            return self._client
        except Exception as exc:
            raise RuntimeError(
                f"Failed to connect to Docker daemon: {exc}. "
                "Ensure Docker is running and the current user has permission."
            ) from exc

    def is_container_running(
        self,
        container_id_or_name: Optional[str] = None
    ) -> bool:
        """
        Checks if an Open WebUI container is currently running.

        Args:
            container_id_or_name: Specific container name or ID to check. If None,
                                  scans for any running container created by Firedamp
                                  or matching the Open WebUI image repository.

        Returns:
            bool: True if at least one matching container is in 'running' state, False otherwise.
        """
        client = self.client

        if container_id_or_name:
            try:
                container = client.containers.get(container_id_or_name)
                # Reload container metadata to get current live status
                container.reload()
                is_running = container.status.lower() == "running"
                logger.debug(
                    f"Container '{container_id_or_name}' status: {container.status} (running={is_running})"
                )
                return is_running
            except NotFound:
                logger.debug(f"Container '{container_id_or_name}' not found.")
                return False
            except APIError as exc:
                logger.error(f"Error querying container '{container_id_or_name}': {exc}")
                return False

        # Scan for any running containers matching image repository or name prefix
        running_containers = self.get_running_containers()
        return len(running_containers) > 0

    def get_running_containers(self) -> List["Container"]:
        """
        Retrieves all running containers that belong to Open WebUI or Firedamp.

        Returns:
            List[Container]: List of running docker Container instances.
        """
        client = self.client
        matched: List["Container"] = []

        try:
            # Query running containers only
            containers = client.containers.list(filters={"status": "running"})
            for container in containers:
                image_tags = container.image.tags if container.image else []
                name = container.name or ""

                matches_repo = any(self.image_repo in tag for tag in image_tags)
                matches_name = name.startswith(self.DEFAULT_CONTAINER_PREFIX)

                if matches_repo or matches_name:
                    matched.append(container)
        except APIError as exc:
            logger.error(f"Failed to list running containers: {exc}")

        return matched

    def pull_image(
        self,
        version: str = "main",
        force: bool = False
    ) -> "Image":
        """
        Pulls a specific version tag of the Open WebUI image from the registry.

        Args:
            version: Image tag to pull (e.g., '0.3.10', 'v0.1.124', 'main', 'latest').
            force: If False, checks local image cache first before pulling from remote.

        Returns:
            Image: The pulled or cached Docker Image object.
        """
        client = self.client
        image_tag = f"{self.image_repo}:{version}"

        if not force:
            try:
                local_image = client.images.get(image_tag)
                logger.info(f"Using cached local image: {image_tag} ({local_image.short_id})")
                return local_image
            except NotFound:
                logger.info(f"Image {image_tag} not found locally. Pulling from registry...")

        logger.info(f"Pulling image {image_tag} from registry...")
        try:
            # Docker SDK pull accepts repository and tag separately
            image = client.images.pull(self.image_repo, tag=version)
            logger.info(f"Successfully pulled image: {image_tag} (ID: {image.short_id})")
            return image
        except APIError as exc:
            raise RuntimeError(f"Failed to pull image {image_tag}: {exc}") from exc

    def teardown(
        self,
        container_id_or_name: Optional[str] = None,
        timeout: int = 10,
        remove_volumes: bool = True
    ) -> int:
        """
        Cleanly stops and removes Open WebUI container(s).

        Args:
            container_id_or_name: Target container to teardown. If None, tears down
                                  the currently active container managed by this instance,
                                  or all Firedamp-created Open WebUI containers.
            timeout: Grace period in seconds to wait for container to stop before SIGKILL.
            remove_volumes: Whether to delete anonymous volumes attached to the container.

        Returns:
            int: Number of containers cleanly torn down.
        """
        client = self.client
        targets: List["Container"] = []

        if container_id_or_name:
            try:
                targets.append(client.containers.get(container_id_or_name))
            except NotFound:
                logger.warning(f"Teardown target '{container_id_or_name}' not found.")
                return 0
        elif self._active_container:
            targets.append(self._active_container)
        else:
            # Clean up all containers matching firedamp-openwebui prefix
            all_containers = client.containers.list(all=True)
            for c in all_containers:
                if c.name and c.name.startswith(self.DEFAULT_CONTAINER_PREFIX):
                    targets.append(c)

        count = 0
        for container in targets:
            c_name = container.name
            c_id = container.short_id
            try:
                # Reload to check real-time state
                container.reload()
                if container.status.lower() == "running":
                    logger.info(f"Stopping container '{c_name}' ({c_id}) [timeout={timeout}s]...")
                    container.stop(timeout=timeout)

                logger.info(f"Removing container '{c_name}' ({c_id}) [v={remove_volumes}]...")
                container.remove(v=remove_volumes, force=True)
                count += 1
                logger.info(f"Container '{c_name}' ({c_id}) successfully torn down.")
            except NotFound:
                logger.debug(f"Container '{c_name}' was already removed.")
            except APIError as exc:
                logger.error(f"Error tearing down container '{c_name}': {exc}")

        if self._active_container and self._active_container in targets:
            self._active_container = None

        return count

    def _find_free_port(self) -> int:
        """Finds an available TCP port on the host."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", 0))
            return s.getsockname()[1]

    def start(
        self,
        version: str = "latest",
        timeout: int = 90,
        env_vars: Optional[Dict[str, str]] = None,
        port: Optional[int] = None,
        cpu_only: bool = False,
    ) -> TargetEnvironment:
        """
        Provisions and launches an Open WebUI container using the Docker SDK.

        Args:
            version: Image version tag to pull and run.
            timeout: Maximum seconds to wait for HTTP readiness.
            env_vars: Additional environment variables for the container.
            port: Specific host port to bind. If None, an ephemeral port is selected.
            cpu_only: If True, disable Ollama API and use built-in CPU pipelines
                      so the container runs without GPU or a local Ollama instance.

        Returns:
            TargetEnvironment: Configured target connection environment.
        """
        client = self.client

        # Ensure image is present
        self.pull_image(version=version)

        host_port = port or self._find_free_port()
        container_name = f"{self.DEFAULT_CONTAINER_PREFIX}-{host_port}"
        image_tag = f"{self.image_repo}:{version}"

        container_env = {
            "WEBUI_AUTH": "True",
            "ENV": "test",
            "ENABLE_SIGNUP": "True",
        }

        if cpu_only:
            # Disable Ollama so Open WebUI doesn't need a running LLM backend.
            # RAG indexing uses the built-in SentenceTransformer (CPU) by default.
            container_env.update({
                "ENABLE_OLLAMA_API": "False",
                "OLLAMA_BASE_URL": "",
                "RAG_EMBEDDING_ENGINE": "",  # empty = default CPU SentenceTransformer
            })

        if env_vars:
            container_env.update(env_vars)

        logger.info(f"Starting Open WebUI container '{container_name}' on port {host_port}...")
        try:
            container = client.containers.run(
                image=image_tag,
                name=container_name,
                detach=True,
                ports={"8080/tcp": host_port},
                environment=container_env,
                labels={"managed_by": "firedamp", "version": version},
            )
            self._active_container = container
        except APIError as exc:
            raise RuntimeError(f"Failed to run container '{container_name}': {exc}") from exc

        env = TargetEnvironment(
            name="openwebui",
            base_url=f"http://localhost:{host_port}",
            host="localhost",
            port=host_port,
            container_id=container.short_id,
            managed_by_docker=True,
            metadata={"container_name": container_name, "image": image_tag}
        )

        # Readiness polling
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.is_healthy(env):
                logger.info(f"Open WebUI container '{container_name}' is healthy and ready.")
                return env
            time.sleep(2)

        # Teardown on timeout failure
        self.teardown(container.id)
        raise TimeoutError(
            f"Open WebUI container '{container_name}' failed health check within {timeout}s."
        )

    def is_healthy(self, env: TargetEnvironment) -> bool:
        """Checks if the Open WebUI container HTTP server is responding."""
        try:
            with urllib.request.urlopen(f"{env.base_url}/", timeout=2) as resp:
                return resp.status in (200, 301, 302)
        except Exception:
            return False

    def stop(self, env: TargetEnvironment) -> None:
        """Stop implementation satisfying BaseTargetManager interface."""
        self.teardown(container_id_or_name=env.container_id)

    def __enter__(self) -> "OpenWebUIContainerManager":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.teardown()


# Backward-compatible alias
DockerTargetManager = OpenWebUIContainerManager
