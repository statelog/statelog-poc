from __future__ import annotations

from datetime import datetime
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class Policy:
    name: str
    effect: str
    policy_id: int | None = None
    priority: int = 100
    version: int = 1
    request_types: tuple[str, ...] = ()
    countries: tuple[str, ...] = ()
    device_ids: tuple[str, ...] = ()
    max_risk_score: int | None = None
    min_trust_score: int | None = None
    max_transaction_amount: float | None = None
    allowed_start_hour: int | None = None
    allowed_end_hour: int | None = None
    valid_from: datetime | None = None
    expires_at: datetime | None = None

@dataclass(frozen=True)
class PolicyDecision:
    matched: bool
    allow: bool | None
    reason: str
    policy_name: str | None = None
    policy_version: int | None = None
    policy_id: int | None = None

@dataclass(frozen=True)
class PolicySimulation:
    decision: PolicyDecision
    evaluated_policies: int
    matched: bool
    policy_name: str | None
    policy_version: int | None


class PolicyEngine:
    def __init__(self, policies: Iterable[Policy] | None = None) -> None:
        self.policies = sorted(
            list(policies or []),
            key=lambda policy: (
                policy.priority,
                0 if policy.effect.lower() == "deny" else 1,
                policy.name,
                policy.policy_id if policy.policy_id is not None else 0,
                policy.version,
            ),
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
                context=context,
            ):
                continue

            effect = policy.effect.lower()

            if effect == "deny":
                return PolicyDecision(
                    matched=True,
                    allow=False,
                    reason=f"policy_deny:{policy.name}",
                    policy_name=policy.name,
                    policy_version=policy.version,
                    policy_id=policy.policy_id,
                )

            if effect == "allow":
                return PolicyDecision(
                    matched=True,
                    allow=True,
                    reason=f"policy_allow:{policy.name}",
                    policy_name=policy.name,
                    policy_version=policy.version,
                    policy_id=policy.policy_id,
                )

        return PolicyDecision(
            matched=False,
            allow=None,
            reason="no_policy_match",
        )

    def simulate(
        self,
        *,
        request_type: str,
        device_id: str,
        country_code: str,
        risk_score: int,
        trust_score: int | None = None,
        context: dict[str, Any] | None = None,
    ) -> PolicySimulation:
        decision = self.evaluate(
            request_type=request_type,
            device_id=device_id,
            country_code=country_code,
            risk_score=risk_score,
            trust_score=trust_score,
            context=context,
        )

        return PolicySimulation(
            decision=decision,
            evaluated_policies=len(self.policies),
            matched=decision.matched,
            policy_name=decision.policy_name,
            policy_version=decision.policy_version,
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
        context: dict[str, Any],
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

        if policy.max_transaction_amount is not None:
            transaction_amount = context.get("transaction_amount")

            if transaction_amount is None:
                return False

            if transaction_amount > policy.max_transaction_amount:
                return False

        if (
            policy.allowed_start_hour is not None
            or policy.allowed_end_hour is not None
        ):
            hour = context.get("hour")

            if hour is None:
                return False

            start = policy.allowed_start_hour
            end = policy.allowed_end_hour

            if start is not None and end is not None:
                if start < end:
                    if hour < start or hour >= end:
                        return False
                elif start > end:
                    if hour < start and hour >= end:
                        return False
            elif start is not None:
                if hour < start:
                    return False
            elif end is not None:
                if hour >= end:
                    return False

        return True