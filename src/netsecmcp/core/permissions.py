from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable, Sequence

from ..config import DEFAULT_CONFIG
from .exceptions import ScanValidationError, TargetAuthorizationError


@dataclass(frozen=True)
class AuthorizationDecision:
    authorized: bool
    target: str
    reason: str = ""


class AuthorizationEngine:
    def __init__(self, allowed_cidrs: Sequence[str] | None = None):
        self.allowed_cidrs = tuple(allowed_cidrs or DEFAULT_CONFIG.allowed_cidrs)

    def _normalize(self, target: str) -> str:
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except ValueError:
            return str(ipaddress.ip_address(target))

    def is_target_allowed(self, target: str) -> bool:
        try:
            candidate = ipaddress.ip_network(target, strict=False)
        except ValueError:
            try:
                candidate = ipaddress.ip_address(target)
            except ValueError as exc:
                raise ScanValidationError(f"Invalid scan target: {target!r}") from exc
            candidate = ipaddress.ip_network(f"{candidate}/32", strict=False)

        allowed = [ipaddress.ip_network(cidr, strict=False) for cidr in self.allowed_cidrs]
        for net in allowed:
            if candidate.version != net.version:
                continue
            if candidate.subnet_of(net):
                return True
        return False

    def authorize(self, target: str) -> AuthorizationDecision:
        try:
            normalized = self._normalize(target)
        except ValueError as exc:
            raise ScanValidationError(f"Invalid target value: {target!r}") from exc

        if not self.is_target_allowed(normalized):
            return AuthorizationDecision(
                authorized=False,
                target=normalized,
                reason=(
                    "Target is outside the configured allowlist. Only private lab ranges are authorized by default."
                ),
            )
        return AuthorizationDecision(authorized=True, target=normalized, reason="Authorized for lab scanning.")

    def require_authorization(self, target: str) -> str:
        decision = self.authorize(target)
        if not decision.authorized:
            raise TargetAuthorizationError(decision.reason)
        return decision.target
