from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


@dataclass
class ScanRecord:
    target: str
    profile: str = "lab-safe"
    started_at: datetime = field(default_factory=datetime.utcnow)
    finished_at: datetime | None = None
    status: str = "pending"
    assets: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
