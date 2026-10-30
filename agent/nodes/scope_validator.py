from __future__ import annotations

from src.netsecmcp.core.permissions import AuthorizationEngine
from ..state import AssessmentState


def validate_scope(state: AssessmentState) -> AssessmentState:
    decision = AuthorizationEngine().authorize(state.target)
    state.authorized = decision.authorized
    state.phase = "scope_validation"
    if not decision.authorized:
        state.findings.append(f"Scope validation rejected: {decision.reason}")
    return state
