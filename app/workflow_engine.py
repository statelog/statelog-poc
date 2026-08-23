from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkflowDecision:
    decision_source: str
    decision_path: tuple[str, ...]


class WorkflowEngine:
    def evaluate(
        self,
        *,
        risk_allowed: bool,
        policy_matched: bool,
        policy_allowed: bool | None,
        final_allowed: bool,
    ) -> WorkflowDecision:
        if not risk_allowed:
            decision_source = "risk"
        elif policy_matched:
            decision_source = "policy"
        else:
            decision_source = "risk"

        decision_path = (
            "risk_evaluated",
            "policy_checked",
            "policy_matched" if policy_matched else "no_policy_match",
            "final_allow" if final_allowed else "final_deny",
        )

        return WorkflowDecision(
            decision_source=decision_source,
            decision_path=decision_path,
        )