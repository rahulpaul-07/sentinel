"""
sentinel/sandbox.py
-------------------
Run untrusted code inside a locked-down, disposable Docker container.

The Validator will use this to execute proof-of-concept exploit code. That code is
UNTRUSTED, so the container is deliberately caged:

  --network none      no external network access at all
  --memory / --cpus   capped resources (can't exhaust the host)
  --rm                the container is deleted the moment it exits
  a hard timeout      we kill anything that runs too long

We shell out to the `docker` CLI with subprocess so every security flag is visible
in the code -- you should be able to point at each one and say why it's there.
"""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SandboxResult:
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool


DEFAULT_IMAGE = "python:3.12-slim"


class Sandbox:
    def __init__(
        self,
        image: str = DEFAULT_IMAGE,
        memory: str = "256m",
        cpus: str = "1.0",
        timeout_seconds: int = 20,
    ) -> None:
        self.image = image
        self.memory = memory
        self.cpus = cpus
        self.timeout_seconds = timeout_seconds

    def run(self, command: str, workdir: Path | None = None) -> SandboxResult:
        """Run a shell command inside a caged container and capture its output.

        If `workdir` is given, that host folder is mounted READ-ONLY at /work inside
        the container, so code can be run but never modified.
        """
        # A unique name lets us force-kill this exact container if it hangs.
        name = f"sentinel-sbx-{uuid.uuid4().hex[:8]}"

        docker_cmd = [
            "docker", "run",
            "--rm",                       # delete the container when it exits
            "--name", name,
            "--network", "none",          # NO network access
            f"--memory={self.memory}",    # cap RAM
            f"--cpus={self.cpus}",        # cap CPU
        ]

        if workdir is not None:
            host = Path(workdir).resolve()
            docker_cmd += ["-v", f"{host}:/work:ro", "-w", "/work"]

        # The image, then run the command through a shell inside the container.
        docker_cmd += [self.image, "sh", "-c", command]

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
            )
            return SandboxResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as e:
            # The CLI was killed by the timeout; make sure the container is gone too.
            subprocess.run(["docker", "kill", name], capture_output=True, text=True)
            return SandboxResult(
                exit_code=-1,
                stdout=e.stdout or "",
                stderr=(e.stderr or "") + "\n[sandbox] timed out",
                timed_out=True,
            )