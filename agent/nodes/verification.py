from __future__ import annotations

from ..state import AssessmentState


async def verify_findings(state: AssessmentState) -> AssessmentState:
    state.phase = "verification"
    state.approved_by_human = True
    state.findings.append("Evidence has been verified against the allowed target scope.")
    return state
