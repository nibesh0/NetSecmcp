from __future__ import annotations

from ..state import AssessmentState


async def analyze_findings(state: AssessmentState) -> AssessmentState:
    state.phase = "analysis"
    if state.metadata.get("ports"):
        state.findings.append("Port assessment suggests the host is reachable and responding on expected services.")
    else:
        state.findings.append("No open services were observed during the initial assessment.")
    return state
