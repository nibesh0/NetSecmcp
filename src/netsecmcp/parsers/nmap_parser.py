from __future__ import annotations

import re


def parse_nmap_summary(output: str) -> dict[str, list[str]]:
    hosts: list[str] = []
    ports: list[str] = []
    services: list[str] = []
    vulnerabilities: list[str] = []

    for line in output.splitlines():
        text = line.strip()
        if not text:
            continue
        lowered = text.lower()
        host_match = re.search(r"\b(?:nmap scan report for|host is up)\b.*?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)", text)
        if host_match:
            hosts.append(host_match.group(1))
        if "/tcp" in text and "open" in lowered and "nmap" not in lowered:
            match = re.search(r"(\d+)/tcp", text)
            if match:
                ports.append(match.group(1))
        if "open" in lowered and ("tcp" in lowered or "udp" in lowered):
            services.append(text)
        if any(token in lowered for token in ("cve", "vulnerable", "weak cipher", "security warning")):
            vulnerabilities.append(text)
    return {"hosts": hosts, "ports": ports, "services": services, "vulnerabilities": vulnerabilities}
