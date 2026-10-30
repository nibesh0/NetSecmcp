from __future__ import annotations

import ipaddress
import re
from typing import Iterable, Sequence

from ..config import DEFAULT_CONFIG
from .exceptions import ScanValidationError


def normalize_target(value: str) -> str:
    if not value or not value.strip():
        raise ScanValidationError("Target must not be empty.")
    return value.strip()


def validate_ip_target(value: str) -> str:
    target = normalize_target(value)
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            network = ipaddress.ip_network(target, strict=False)
            if network.prefixlen > 32 and ":" not in target:
                raise ValueError
            return str(network)
        except ValueError as exc:
            raise ScanValidationError(f"Invalid target: {target!r}") from exc


def validate_network_target(value: str) -> str:
    target = normalize_target(value)
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError as exc:
        raise ScanValidationError(f"Invalid network target: {target!r}") from exc
    if network.num_addresses > DEFAULT_CONFIG.max_scan_range:
        raise ScanValidationError(
            f"Target range too large: {network.num_addresses} addresses exceeds max_scan_range={DEFAULT_CONFIG.max_scan_range}."
        )
    return str(network)


def validate_port_range(value: str, max_ports: int = 1024) -> list[int]:
    if not value or not value.strip():
        raise ScanValidationError("Port range must not be empty.")
    ports: list[int] = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            try:
                start = int(start_s)
                end = int(end_s)
            except ValueError as exc:
                raise ScanValidationError(f"Invalid port range item: {part!r}") from exc
            if not (1 <= start <= end <= 65535):
                raise ScanValidationError(f"Port range out of bounds: {part!r}")
            ports.extend(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError as exc:
                raise ScanValidationError(f"Invalid port value: {part!r}") from exc
            if not (1 <= port <= 65535):
                raise ScanValidationError(f"Port out of bounds: {part!r}")
            ports.append(port)
    unique_ports = sorted(set(ports))
    if len(unique_ports) > max_ports:
        raise ScanValidationError(
            f"Requested {len(unique_ports)} ports exceeds the configured max_ports={max_ports}."
        )
    return unique_ports


def validate_timeout(value: int | float, config=None) -> int:
    config = config or DEFAULT_CONFIG
    timeout = int(value)
    if timeout <= 0:
        raise ScanValidationError("Timeout must be positive.")
    if timeout > config.max_execution_time:
        raise ScanValidationError(
            f"Timeout {timeout}s exceeds the configured maximum of {config.max_execution_time}s."
        )
    return timeout


def validate_executable_name(executable: str, allowed: Sequence[str]) -> str:
    executable = executable.strip()
    if not executable or "/" in executable and not executable.startswith("/"):
        raise ScanValidationError(f"Executable name is invalid: {executable!r}")
    if executable not in allowed:
        raise ScanValidationError(f"Executable {executable!r} is not allowlisted.")
    return executable
