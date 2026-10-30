from __future__ import annotations

from ..core.executor import execute_command
from ..core.permissions import AuthorizationEngine


async def nuclei_scan(target: str, template: str = "dns") -> dict:
    auth = AuthorizationEngine()
    authorized = auth.require_authorization(target)
    result = await execute_command("nuclei", "-t", template, "-u", authorized, timeout=90)
    return {"authorized_target": authorized, "template": template, "result": result}
