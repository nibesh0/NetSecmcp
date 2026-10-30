from __future__ import annotations

from ..state import AssessmentState


async def report(state: AssessmentState) -> AssessmentState:
    state.phase = "reporting"
    state.findings.append(f"Assessment complete for {state.target}.")
    return state
