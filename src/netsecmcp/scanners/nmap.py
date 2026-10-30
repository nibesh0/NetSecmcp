from __future__ import annotations

from ..core.executor import execute_command
from ..core.permissions import AuthorizationEngine
from ..core.validator import validate_network_target, validate_port_range
from ..parsers.nmap_parser import parse_nmap_summary


async def host_discovery(target: str, profile: str = "lab-safe") -> dict:
    auth = AuthorizationEngine()
    authorized = auth.require_authorization(target)
    network = validate_network_target(authorized)
    result = await execute_command("nmap", "-sn", network, timeout=120)
    parsed = parse_nmap_summary(result.stdout + "\n" + result.stderr)
    return {"authorized_target": network, "result": result, "parsed": parsed}


async def port_scan(target: str, port_range: str = "80,443,22", profile: str = "lab-safe") -> dict:
    auth = AuthorizationEngine()
    authorized = auth.require_authorization(target)
    ports = validate_port_range(port_range, max_ports=256)
    port_arg = ",".join(str(p) for p in ports)
    result = await execute_command("nmap", "-Pn", "-sT", "-p", port_arg, authorized, timeout=120)
    parsed = parse_nmap_summary(result.stdout + "\n" + result.stderr)
    return {"authorized_target": authorized, "ports": port_arg, "result": result, "parsed": parsed}


async def service_scan(target: str, port_range: str = "80,443,22") -> dict:
    auth = AuthorizationEngine()
    authorized = auth.require_authorization(target)
    ports = validate_port_range(port_range, max_ports=256)
    port_arg = ",".join(str(p) for p in ports)
    result = await execute_command("nmap", "-sV", "-Pn", "-p", port_arg, authorized, timeout=150)
    parsed = parse_nmap_summary(result.stdout + "\n" + result.stderr)
    return {"authorized_target": authorized, "ports": port_arg, "result": result, "parsed": parsed}


async def ssl_assessment(target: str, port: str = "443") -> dict:
    auth = AuthorizationEngine()
    authorized = auth.require_authorization(target)
    result = await execute_command("openssl", "s_client", "-connect", f"{authorized}:{port}", "-brief", timeout=60)
    return {"authorized_target": authorized, "port": port, "result": result}
