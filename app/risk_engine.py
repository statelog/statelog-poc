from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .models import RequestLog
from .time_utils import utcnow_naive

RISK_SIGNAL_SCORES = {
    "failure_burst": 35,
    "new_device": 15,
    "new_ip": 10,
    "geo_change": 15,
    "transfer_velocity": 30,
    "sensitive_action": 10,
}

@dataclass
class RiskDecision:
    allow: bool
    risk_score: int
    trust_score: int
    reason: str
    signals: tuple[str, ...] = ()


class RiskEngine:
    def evaluate(
        self,
        *,
        request_type: str,
        device_id: str,
        ip_address: str,
        country_code: str,
        historical_logs: Iterable[RequestLog],
    ) -> RiskDecision:
        score = 0
        reasons: list[str] = []
        logs = sorted(list(historical_logs), key=lambda item: item.created_at)
        now = utcnow_naive()

        recent_failures = [l for l in logs if (now - l.created_at) <= timedelta(minutes=15) and not l.allowed]
        if len(recent_failures) >= 3:
            score += RISK_SIGNAL_SCORES["failure_burst"]
            reasons.append("failure_burst")

        recent_logs = logs[-5:]
        if recent_logs and all(l.device_id != device_id for l in recent_logs):
            score += RISK_SIGNAL_SCORES["new_device"]
            reasons.append("new_device")

        if recent_logs and all(l.ip_hash != ip_address for l in recent_logs):
            score += RISK_SIGNAL_SCORES["new_ip"]
            reasons.append("new_ip")

        recent_countries = {l.country_code for l in logs[-10:]}
        if recent_countries and country_code not in recent_countries:
            score += RISK_SIGNAL_SCORES["geo_change"]
            reasons.append("geo_change")

        if request_type == "ownership_transfer":
            recent_transfers = [l for l in logs if l.request_type == "ownership_transfer" and (now - l.created_at) <= timedelta(hours=1)]
            if len(recent_transfers) >= 2:
                score += RISK_SIGNAL_SCORES["transfer_velocity"]
                reasons.append("transfer_velocity")
            else:
                score += RISK_SIGNAL_SCORES["sensitive_action"]
                reasons.append("sensitive_action")

        if score >= 70:
            return RiskDecision(
                allow=False,
                risk_score=score,
                trust_score=max(0, min(100, 100 - score)),
                reason=";".join(reasons) or "deny",
                signals=tuple(reasons),
            )

        return RiskDecision(
            allow=True,
            risk_score=score,
            trust_score=max(0, min(100, 100 - score)),
            reason=";".join(reasons) or "allowed",
            signals=tuple(reasons),
        )