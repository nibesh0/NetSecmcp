from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any


class ScanScheduler:
    """Simple bounded-concurrency scheduler for scan execution."""

    def __init__(self, max_concurrency: int = 4):
        self.max_concurrency = max_concurrency
        self._sem = asyncio.Semaphore(max_concurrency)

    async def run(self, func: Callable[..., Awaitable[Any]], *args, **kwargs):
        async with self._sem:
            return await func(*args, **kwargs)
