from __future__ import annotations

from .database import InMemoryScanRepository


class ScanRepository(InMemoryScanRepository):
    """Compatibility shim for the scan history repository."""

    pass
