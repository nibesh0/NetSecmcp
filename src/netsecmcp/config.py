from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Tuple


DEFAULT_ALLOWED_CIDRS: Tuple[str, ...] = (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "::1/128",
    "fc00::/7",
)


@dataclass(frozen=True)
class ScanProfile:
    name: str = "lab-safe"
    intensity: str = "low"
    max_hosts: int = 64
    max_ports: int = 1024
    timeout_seconds: int = 180
    rate_limit_per_minute: int = 30
    allowed_ports: Tuple[int, ...] = (22, 80, 443, 53, 3389, 8080, 8443)


@dataclass
class NetSecConfig:
    allowed_cidrs: Tuple[str, ...] = DEFAULT_ALLOWED_CIDRS
    default_target: str = "192.168.1.0/24"
    max_scan_range: int = 256
    max_ports_per_scan: int = 1024
    max_execution_time: int = 300
    max_output_bytes: int = 200000
    allowed_executables: Tuple[str, ...] = (
        "echo",
        "python",
        "nmap",
        "masscan",
        "zmap",
        "openssl",
        "sslscan",
        "nuclei",
    )
    profiles: dict[str, ScanProfile] = field(
        default_factory=lambda: {
            "lab-safe": ScanProfile(name="lab-safe", intensity="low", max_hosts=64, max_ports=1024, timeout_seconds=180, rate_limit_per_minute=30),
            "standard": ScanProfile(name="standard", intensity="medium", max_hosts=128, max_ports=2048, timeout_seconds=300, rate_limit_per_minute=20),
            "deep": ScanProfile(name="deep", intensity="high", max_hosts=32, max_ports=512, timeout_seconds=600, rate_limit_per_minute=10),
        }
    )

    def get_profile(self, name: str) -> ScanProfile:
        return self.profiles.get(name, self.profiles["lab-safe"])


DEFAULT_CONFIG = NetSecConfig()
