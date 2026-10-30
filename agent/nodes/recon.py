from __future__ import annotations

from src.netsecmcp.scanners.nmap import host_discovery
from ..state import AssessmentState


async def recon(state: AssessmentState) -> AssessmentState:
    data = await host_discovery(state.target, profile=state.profile)
    state.phase = "reconnaissance"
    state.metadata["recon"] = data
    state.findings.append(f"Recon completed for {state.target}")
    return state
