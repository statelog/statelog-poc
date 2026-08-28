from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class WorkflowDecision:
    decision_source: str
    decision_path: tuple[str, ...]

@dataclass(frozen=True)
class WorkflowConfig:
    include_risk_step: bool = True
    include_policy_step: bool = True
    execution_mode: str = "risk_first"

class WorkflowEngine:
    def __init__(self, config: WorkflowConfig | None = None) -> None:
        self.config = config or WorkflowConfig()

    @staticmethod
    def resolve_allowed(
        *,
        risk_allowed: bool,
        policy_matched: bool,
        policy_allowed: bool | None,
    ) -> bool:
        if not risk_allowed:
            return False

        if policy_matched and policy_allowed is False:
            return False

        return True
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

        path: list[str] = []

        if self.config.execution_mode == "policy_first":
            if self.config.include_policy_step:
                path.append("policy_checked")
                path.append(
                    "policy_matched"
                    if policy_matched
                    else "no_policy_match"
                )

            if self.config.include_risk_step:
                path.append("risk_evaluated")

        else:
            if self.config.include_risk_step:
                path.append("risk_evaluated")

            if self.config.include_policy_step:
                path.append("policy_checked")
                path.append(
                    "policy_matched"
                    if policy_matched
                    else "no_policy_match"
                )

        path.append(
            "final_allow"
            if final_allowed
            else "final_deny"
        )

        decision_path = tuple(path)
        
        return WorkflowDecision(
            decision_source=decision_source,
            decision_path=decision_path,
        )
