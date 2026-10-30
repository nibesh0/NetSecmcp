from __future__ import annotations

from src.netsecmcp.scanners.nmap import port_scan
from ..state import AssessmentState


async def scan_assets(state: AssessmentState) -> AssessmentState:
    data = await port_scan(state.target, port_range="80,443,22", profile=state.profile)
    state.phase = "scanning"
    state.metadata["ports"] = data
    state.findings.append(f"Port scan completed for {state.target}")
    return state
