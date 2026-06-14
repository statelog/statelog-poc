from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Iterable

from .models import RequestLog
from .time_utils import utcnow_naive


@dataclass
class RiskDecision:
    allow: bool
    risk_score: int
    reason: str


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
            score += 35
            reasons.append("failure_burst")

        recent_logs = logs[-5:]
        if recent_logs and all(l.device_id != device_id for l in recent_logs):
            score += 15
            reasons.append("new_device")

        if recent_logs and all(l.ip_hash != ip_address for l in recent_logs):
            score += 10
            reasons.append("new_ip")

        recent_countries = {l.country_code for l in logs[-10:]}
        if recent_countries and country_code not in recent_countries:
            score += 15
            reasons.append("geo_change")

        if request_type == "ownership_transfer":
            recent_transfers = [l for l in logs if l.request_type == "ownership_transfer" and (now - l.created_at) <= timedelta(hours=1)]
            if len(recent_transfers) >= 2:
                score += 30
                reasons.append("transfer_velocity")
            else:
                score += 10
                reasons.append("sensitive_action")

        if score >= 70:
            return RiskDecision(allow=False, risk_score=score, reason=",".join(reasons) or "deny")
        return RiskDecision(allow=True, risk_score=score, reason=",".join(reasons) or "allowed")
