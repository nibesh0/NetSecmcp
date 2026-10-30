from __future__ import annotations

from ..core.executor import execute_command
from ..core.permissions import AuthorizationEngine


async def sslscan(target: str, port: str = "443") -> dict:
    auth = AuthorizationEngine()
    authorized = auth.require_authorization(target)
    result = await execute_command("sslscan", f"{authorized}:{port}", timeout=60)
    return {"authorized_target": authorized, "port": port, "result": result}
