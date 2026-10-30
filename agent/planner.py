from __future__ import annotations

from .state import AssessmentState


class AssessmentPlanner:
    def plan(self, state: AssessmentState) -> list[str]:
        return [
            "scope_validation",
            "reconnaissance",
            "port_assessment",
            "service_identification",
            "verification",
            "reporting",
        ]
