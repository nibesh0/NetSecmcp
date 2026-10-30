from __future__ import annotations

from fastapi import FastAPI

app = FastAPI(title="NetSecMCP API", version="0.1.0")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/status")
async def status() -> dict[str, str]:
    return {"service": "NetSecMCP", "mode": "secure-lab"}
