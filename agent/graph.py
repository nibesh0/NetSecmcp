from __future__ import annotations

from typing import Any

try:
    from langgraph.graph import StateGraph
except Exception:  # pragma: no cover
    StateGraph = None

from .nodes.scope_validator import validate_scope
from .nodes.recon import recon
from .nodes.scanning import scan_assets
from .nodes.analysis import analyze_findings
from .nodes.verification import verify_findings
from .nodes.reporting import report
from .state import AssessmentState


class AssessmentGraph:
    def __init__(self):
        self.graph = self._build_graph() if StateGraph else None

    def _build_graph(self):
        graph = StateGraph(AssessmentState)
        graph.add_node("scope_validator", validate_scope)
        graph.add_node("recon", recon)
        graph.add_node("scanning", scan_assets)
        graph.add_node("analysis", analyze_findings)
        graph.add_node("verification", verify_findings)
        graph.add_node("reporting", report)
        graph.set_entry_point("scope_validator")
        graph.add_edge("scope_validator", "recon")
        graph.add_edge("recon", "scanning")
        graph.add_edge("scanning", "analysis")
        graph.add_edge("analysis", "verification")
        graph.add_edge("verification", "reporting")
        return graph.compile()

    def run(self, state: AssessmentState):
        if self.graph is None:
            return {**state.__dict__, "phase": "reporting"}
        return self.graph.invoke(state)
