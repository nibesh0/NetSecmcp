from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from typing import Sequence

from ..config import DEFAULT_CONFIG
from .exceptions import ExecutionPolicyError
from .validator import validate_executable_name


@dataclass
class CommandResult:
    executable: str
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    duration_seconds: float = 0.0


class AsyncExecutor:
    def __init__(self, config=None, semaphore: asyncio.Semaphore | None = None):
        self.config = config or DEFAULT_CONFIG
        self._semaphore = semaphore or asyncio.Semaphore(4)

    async def execute(
        self,
        executable: str,
        *args: str,
        timeout: int | None = None,
        allowed_executables: Sequence[str] | None = None,
        output_limit: int | None = None,
    ) -> CommandResult:
        allowed = tuple(allowed_executables or self.config.allowed_executables)
        executable = validate_executable_name(executable, allowed)
        timeout_value = timeout or 60
        if timeout_value > self.config.max_execution_time:
            raise ExecutionPolicyError(
                f"Timeout for {executable!r} exceeds the configured maximum of {self.config.max_execution_time}s."
            )

        async with self._semaphore:
            start = asyncio.get_running_loop().time()
            proc = await asyncio.create_subprocess_exec(
                executable,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={**os.environ, "PATH": os.environ.get("PATH", "")},
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=timeout_value,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                elapsed = asyncio.get_running_loop().time() - start
                return CommandResult(
                    executable=executable,
                    args=args,
                    returncode=-1,
                    stdout="",
                    stderr=f"Command timed out after {timeout_value}s.",
                    timed_out=True,
                    duration_seconds=elapsed,
                )

            stdout_text = (stdout_bytes or b"").decode("utf-8", errors="replace")
            stderr_text = (stderr_bytes or b"").decode("utf-8", errors="replace")
            limit = output_limit or self.config.max_output_bytes
            if len(stdout_text) > limit:
                stdout_text = stdout_text[:limit] + "\n... [truncated by NetSecMCP]"
            if len(stderr_text) > limit:
                stderr_text = stderr_text[:limit] + "\n... [truncated by NetSecMCP]"
            elapsed = asyncio.get_running_loop().time() - start
            return CommandResult(
                executable=executable,
                args=args,
                returncode=proc.returncode or 0,
                stdout=stdout_text,
                stderr=stderr_text,
                timed_out=False,
                duration_seconds=elapsed,
            )


async def execute_command(
    executable: str,
    *args: str,
    timeout: int = 60,
    config=None,
    allowed_executables: Sequence[str] | None = None,
) -> CommandResult:
    executor = AsyncExecutor(config=config)
    return await executor.execute(executable, *args, timeout=timeout, allowed_executables=allowed_executables)
