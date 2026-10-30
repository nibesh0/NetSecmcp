# NetSecMCP

NetSecMCP is a secure, modular network security assessment platform designed for authorized lab environments. It combines MCP-compatible tools with a lightweight agentic workflow, centralized authorization checks, and an allowlisted execution engine.

## What changed

The original repository was refactored away from shell-based, unconstrained scanning primitives toward a safer architecture:

- Centralized asynchronous subprocess execution using `asyncio.create_subprocess_exec`
- No `shell=True`
- No string concatenation of untrusted arguments into shell commands
- Executable allowlist enforcement
- Explicit IPv4/IPv6 and CIDR validation
- Private-network default allowlist
- Scan profile enforcement and timeout limits
- Persistent scan history via repository abstraction
- Agentic orchestration skeleton using LangGraph when available

## Core architecture

```text
NetSecMCP/
├── server.py
├── src/netsecmcp/
│   ├── config.py
│   ├── main.py
│   ├── core/
│   │   ├── executor.py
│   │   ├── permissions.py
│   │   ├── validator.py
│   │   ├── scheduler.py
│   │   └── exceptions.py
│   ├── mcp_server/
│   │   └── server.py
│   ├── scanners/
│   │   ├── nmap.py
│   │   ├── masscan.py
│   │   ├── sslscan.py
│   │   └── nuclei.py
│   ├── parsers/
│   │   └── nmap_parser.py
│   ├── models/
│   │   ├── asset.py
│   │   ├── finding.py
│   │   └── scan.py
│   └── storage/
│       ├── database.py
│       └── repository.py
├── agent/
│   ├── graph.py
│   ├── planner.py
│   ├── state.py
│   └── nodes/
│       ├── scope_validator.py
│       ├── recon.py
│       ├── scanning.py
│       ├── analysis.py
│       ├── verification.py
│       └── reporting.py
├── api/
│   └── main.py
├── pyproject.toml
├── Dockerfile
├── requirements.txt
├── README.md
└── tests/
```

## Security principles

- Explicit authorization is required for every scan target.
- Default policy allows only lab-safe private ranges such as `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and loopback ranges.
- Intrusive operations such as credential brute force, stealth scanning, and exploit execution are intentionally removed from the default tool surface.
- Commands are limited to an executable allowlist and are validated before execution.
- Every execution returns structured output and capture limits to prevent runaway or oversized logs.

## MCP tools exposed

The server currently includes safe, authorized tools:

- `authorize_target`
- `scan_network`
- `scan_ports`
- `scan_services`
- `scan_ssl`
- `run_security_assessment`
- `assessment_plan`
- Compatibility aliases: `networkDiscovery`, `portScan`, `osDetection`, `webScan`, `sslScan`

## Typical usage

```python
from netsecmcp.mcp_server.server import mcp

# The tool runner enforces allowed targets and scan limits.
# Example: authorized lab target only.
```

## Running locally

Install the Python dependencies and ensure Nmap is available on `PATH`:

```bash
python -m pip install -r requirements.txt
python server.py
```

The MCP server uses stdio transport. For Docker:

```bash
docker build -t netsecmcp .
docker run --rm -i netsecmcp
```

Scans are restricted to the CIDRs configured in `NetSecConfig.allowed_cidrs` in
`src/netsecmcp/config.py`. The defaults permit private IPv4 lab ranges,
carrier-grade NAT space, and loopback; public targets are denied. Keep the
allowlist narrow and limited to systems you are authorized to assess.

The scanner adapters currently use Nmap for discovery, port, and service scans;
OpenSSL is used for the TLS connection check. Additional adapters are present
for Masscan, sslscan, and Nuclei, but their executables must be installed in the
runtime image before those adapters can be used. Scan history is stored locally
in `.netsecmcp/scan_history.json`.

## Validation

Run the unit and execution-policy tests with:

```bash
python -m unittest discover -s tests -v
```

## Notes

The LangGraph workflow and API are scaffolding and are not enabled as live
assessment interfaces by the MCP server. This project intentionally focuses on
safe, authorized assessment patterns for lab and controlled environments. It
does not implement credential theft, stealth evasion, persistence, or
unauthorized exploitation.
