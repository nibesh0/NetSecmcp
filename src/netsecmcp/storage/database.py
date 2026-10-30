from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class InMemoryScanRepository:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root) if root else Path.cwd() / ".netsecmcp"
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "scan_history.json"

    def save(self, payload: dict[str, Any]) -> dict[str, Any]:
        history = self.load()
        history.append(payload)
        self.path.write_text(json.dumps(history, indent=2), encoding="utf-8")
        return payload

    def load(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except json.JSONDecodeError:
            return []

    def list_recent(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.load()[-limit:]
