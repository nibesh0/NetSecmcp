from __future__ import annotations

from ..core.executor import execute_command
from ..core.permissions import AuthorizationEngine


async def quick_scan(target: str, port_range: str = "80,443,22") -> dict:
    auth = AuthorizationEngine()
    authorized = auth.require_authorization(target)
    result = await execute_command("masscan", "-p", port_range, authorized, "--rate=1000", timeout=120)
    return {"authorized_target": authorized, "result": result}
