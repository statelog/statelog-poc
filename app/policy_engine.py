from __future__ import annotations

from datetime import datetime
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class Policy:
    name: str
    effect: str
    priority: int = 100
    request_types: tuple[str, ...] = ()
    countries: tuple[str, ...] = ()
    device_ids: tuple[str, ...] = ()
    max_risk_score: int | None = None
    min_trust_score: int | None = None
    valid_from: datetime | None = None
    expires_at: datetime | None = None

@dataclass(frozen=True)
class PolicyDecision:
    matched: bool
    allow: bool | None
    reason: str
    policy_name: str | None = None


class PolicyEngine:
    def __init__(self, policies: Iterable[Policy] | None = None) -> None:
        self.policies = sorted(
            list(policies or []),
            key=lambda policy: policy.priority,
        )

    def evaluate(
        self,
        *,
        request_type: str,
        device_id: str,
        country_code: str,
        risk_score: int,
        trust_score: int | None = None,
        context: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        context = context or {}
        now = context.get("now")

        if trust_score is None:
            trust_score = max(0, min(100, 100 - risk_score))

        for policy in self.policies:
            if now is not None:
                if policy.valid_from is not None and now < policy.valid_from:
                    continue

            if policy.expires_at is not None and now > policy.expires_at:
                continue         
            if not self._matches(
                policy,
                request_type=request_type,
                device_id=device_id,
                country_code=country_code,
                risk_score=risk_score,
                trust_score=trust_score,
            ):
                continue

            effect = policy.effect.lower()

            if effect == "deny":
                return PolicyDecision(
                    matched=True,
                    allow=False,
                    reason=f"policy_deny:{policy.name}",
                    policy_name=policy.name,
                )

            if effect == "allow":
                return PolicyDecision(
                    matched=True,
                    allow=True,
                    reason=f"policy_allow:{policy.name}",
                    policy_name=policy.name,
                )

        return PolicyDecision(
            matched=False,
            allow=None,
            reason="no_policy_match",
        )

    @staticmethod
    def _matches(
        policy: Policy,
        *,
        request_type: str,
        device_id: str,
        country_code: str,
        risk_score: int,
        trust_score: int,
    ) -> bool:
        if policy.request_types and request_type not in policy.request_types:
            return False

        if policy.device_ids and device_id not in policy.device_ids:
            return False

        if policy.countries and country_code not in policy.countries:
            return False

        if policy.max_risk_score is not None and risk_score > policy.max_risk_score:
            return False
        if policy.min_trust_score is not None and trust_score < policy.min_trust_score:
            return False

        return True