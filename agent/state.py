from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AssessmentState:
    target: str = "192.168.1.0/24"
    profile: str = "lab-safe"
    authorized: bool = False
    approved_by_human: bool = False
    phase: str = "scope_validation"
    findings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
