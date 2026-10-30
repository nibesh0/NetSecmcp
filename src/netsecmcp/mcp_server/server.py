from __future__ import annotations

import json
from typing import Any

try:
    from mcp.server.fastmcp import FastMCP
except Exception:  # pragma: no cover
    class FastMCP:  # type: ignore[override]
        def __init__(self, name: str):
            self.name = name

        def tool(self):
            def decorator(func):
                return func

            return decorator

        def run(self, transport: str = "stdio") -> None:
            return None

from ..core.permissions import AuthorizationEngine
from ..core.validator import validate_network_target, validate_port_range
from ..scanners.nmap import host_discovery, port_scan, service_scan, ssl_assessment
from ..storage.repository import ScanRepository

mcp = FastMCP("NetSecMCP")
repository = ScanRepository()


def _result_summary(title: str, result: Any) -> str:
    if isinstance(result, dict) and "result" in result:
        payload = result["result"]
        if hasattr(payload, "stdout"):
            text = (payload.stdout or "") + ("\nSTDERR:\n" + payload.stderr if payload.stderr else "")
            return f"{title}\n{text or 'No output returned.'}"
    return f"{title}\n{json.dumps(result, indent=2, default=str)}"


@mcp.tool()
async def authorize_target(target: str) -> str:
    engine = AuthorizationEngine()
    decision = engine.authorize(target)
    if not decision.authorized:
        return f"Authorization denied: {decision.reason}"
    return f"Authorization approved for {decision.target}."


@mcp.tool()
async def scan_network(target: str = "192.168.1.0/24", profile: str = "lab-safe") -> str:
    decision = AuthorizationEngine().authorize(target)
    if not decision.authorized:
        raise ValueError(decision.reason)
    data = await host_discovery(decision.target, profile=profile)
    repository.save({"target": decision.target, "profile": profile, "tool": "scan_network", "data": data})
    return _result_summary(f"Network discovery for {decision.target}", data)


@mcp.tool()
async def scan_ports(target: str = "192.168.1.10", ports: str = "80,443,22", profile: str = "lab-safe") -> str:
    decision = AuthorizationEngine().authorize(target)
    if not decision.authorized:
        raise ValueError(decision.reason)
    data = await port_scan(decision.target, port_range=ports, profile=profile)
    repository.save({"target": decision.target, "profile": profile, "tool": "scan_ports", "data": data})
    return _result_summary(f"Port scan for {decision.target}", data)


@mcp.tool()
async def scan_services(target: str = "192.168.1.10", ports: str = "80,443,22") -> str:
    decision = AuthorizationEngine().authorize(target)
    if not decision.authorized:
        raise ValueError(decision.reason)
    data = await service_scan(decision.target, port_range=ports)
    repository.save({"target": decision.target, "tool": "scan_services", "data": data})
    return _result_summary(f"Service scan for {decision.target}", data)


@mcp.tool()
async def scan_ssl(target: str = "127.0.0.1", port: str = "443") -> str:
    decision = AuthorizationEngine().authorize(target)
    if not decision.authorized:
        raise ValueError(decision.reason)
    data = await ssl_assessment(decision.target, port=port)
    repository.save({"target": decision.target, "tool": "scan_ssl", "data": data})
    return _result_summary(f"SSL assessment for {decision.target}:{port}", data)


@mcp.tool()
async def run_security_assessment(target: str = "192.168.1.0/24", profile: str = "lab-safe") -> str:
    auth = AuthorizationEngine()
    decision = auth.authorize(target)
    if not decision.authorized:
        raise ValueError(decision.reason)
    network = validate_network_target(decision.target)
    host_data = await host_discovery(network, profile=profile)
    port_data = await port_scan(network, port_range="80,443,22", profile=profile)
    service_data = await service_scan(network, port_range="80,443,22")
    summary = {
        "authorized_target": network,
        "profile": profile,
        "discovery": host_data,
        "ports": port_data,
        "services": service_data,
    }
    repository.save({"target": network, "profile": profile, "tool": "run_security_assessment", "data": summary})
    return json.dumps(summary, indent=2, default=str)


@mcp.tool()
async def assessment_plan(target: str = "192.168.1.0/24") -> str:
    decision = AuthorizationEngine().authorize(target)
    if not decision.authorized:
        raise ValueError(decision.reason)
    plan = {
        "target": decision.target,
        "phases": [
            "scope_validation",
            "reconnaissance",
            "port_assessment",
            "service_identification",
            "ssl_review",
            "evidence_summary",
            "reporting",
        ],
        "allowed_by_default": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
    }
    return json.dumps(plan, indent=2)


@mcp.tool()
async def networkDiscovery(target: str = "192.168.1.0/24", profile: str = "lab-safe") -> str:
    return await scan_network(target=target, profile=profile)


@mcp.tool()
async def portScan(target: str = "192.168.1.10", ports: str = "80,443,22", profile: str = "lab-safe") -> str:
    return await scan_ports(target=target, ports=ports, profile=profile)


@mcp.tool()
async def osDetection(target: str = "127.0.0.1") -> str:
    decision = AuthorizationEngine().authorize(target)
    if not decision.authorized:
        raise ValueError(decision.reason)
    result = await service_scan(decision.target, port_range="22,80,443")
    return _result_summary(f"OS and service indicators for {decision.target}", result)


@mcp.tool()
async def webScan(target: str = "127.0.0.1") -> str:
    return await scan_services(target=target, ports="80,443,8080,8443")


@mcp.tool()
async def sslScan(target: str = "127.0.0.1", port: str = "443") -> str:
    return await scan_ssl(target=target, port=port)


if __name__ == "__main__":
    mcp.run(transport="stdio")
