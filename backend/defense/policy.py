"""
Policy Evaluator for Ternline Phase 1: Active Defense.

Responsibilities:
1. Evaluates candidate actions against hierarchical protection policies.
2. Enforces mandatory OBSERVE mode defaults for new tenants.
3. Restricts ENFORCED autonomous execution strictly to bounded low-risk actions (rate limiting, short IP blocks).
4. Strictly requires dual-custody human approval for sensitive actions (API key revocation, session containment) regardless of mode or AI confidence.
5. Tracks and enforces hourly autonomous action rate caps.
"""

import datetime
import logging
from typing import Optional
from sqlalchemy.orm import Session

from backend.models import (
    DefenseActionModel,
    TenantDefensePolicyModel,
)
from backend.schemas.defense import (
    ActionStatus,
    ActionType,
    CandidateResponseAction,
    PlannedResponseAction,
    PolicyEvaluationDecision,
    PolicyEvaluationResult,
    ProtectionMode,
    TenantDefensePolicy,
)

logger = logging.getLogger("cyber_engine.defense.policy")

SENSITIVE_ACTIONS = {
    ActionType.API_KEY_REVOCATION,
    ActionType.ACCOUNT_SESSION_CONTAINMENT,
}


class PolicyEvaluator:
    """
    Evaluates proposed defense actions against tenant-configured policies and safety invariants.
    """

    def __init__(self, db: Session):
        self.db = db

    def evaluate(
        self,
        action: PlannedResponseAction,
        policy_override: Optional[TenantDefensePolicy] = None,
    ) -> PolicyEvaluationResult:
        """
        Evaluates a planned defense action and returns an authoritative PolicyEvaluationResult.
        """
        tenant_id = action.tenant_id
        policy = policy_override or self._load_tenant_policy(tenant_id)

        # 1. Mandatory Safeguard: Sensitive irreversible actions ALWAYS require approval
        if action.action_type in SENSITIVE_ACTIONS:
            return PolicyEvaluationResult(
                decision=PolicyEvaluationDecision.REQUIRE_APPROVAL,
                applied_mode=policy.default_mode,
                requires_dual_custody=True,
                rationale=f"Sensitive action '{action.action_type.value}' mandates dual-custody human approval by policy invariant",
                action_id=action.action_id,
            )

        # 2. Inactive Policy or OBSERVE Mode -> Dry-Run Audit Only
        if not policy.is_active or policy.default_mode == ProtectionMode.OBSERVE:
            return PolicyEvaluationResult(
                decision=PolicyEvaluationDecision.DRY_RUN_LOGGED,
                applied_mode=ProtectionMode.OBSERVE,
                requires_dual_custody=False,
                rationale="Tenant is operating in OBSERVE protection mode (dry-run audit only)",
                action_id=action.action_id,
            )

        # 3. ASSISTED Mode -> Requires Human Approval
        if policy.default_mode == ProtectionMode.ASSISTED:
            return PolicyEvaluationResult(
                decision=PolicyEvaluationDecision.REQUIRE_APPROVAL,
                applied_mode=ProtectionMode.ASSISTED,
                requires_dual_custody=False,
                rationale="Tenant is in ASSISTED mode; human analyst approval required prior to execution",
                action_id=action.action_id,
            )

        # 4. ENFORCED Mode -> Autonomous Execution for Authorized Bounded Actions
        if policy.default_mode == ProtectionMode.ENFORCED:
            # Check if action type is explicitly authorized for autonomous containment
            if action.action_type not in policy.allowed_autonomous_actions:
                return PolicyEvaluationResult(
                    decision=PolicyEvaluationDecision.REQUIRE_APPROVAL,
                    applied_mode=ProtectionMode.ENFORCED,
                    requires_dual_custody=False,
                    rationale=f"Action type '{action.action_type.value}' is not whitelisted for autonomous execution",
                    action_id=action.action_id,
                )

            # Check bounded TTL limit
            if action.ttl_seconds and action.ttl_seconds > policy.max_autonomous_ttl_seconds:
                return PolicyEvaluationResult(
                    decision=PolicyEvaluationDecision.REQUIRE_APPROVAL,
                    applied_mode=ProtectionMode.ENFORCED,
                    requires_dual_custody=False,
                    rationale=f"Action TTL ({action.ttl_seconds}s) exceeds max autonomous threshold ({policy.max_autonomous_ttl_seconds}s)",
                    action_id=action.action_id,
                )

            # Check autonomous hourly execution quota to prevent runaway containment
            hourly_count = self._get_recent_autonomous_action_count(tenant_id)
            if hourly_count >= policy.max_autonomous_actions_per_hour:
                return PolicyEvaluationResult(
                    decision=PolicyEvaluationDecision.REQUIRE_APPROVAL,
                    applied_mode=ProtectionMode.ENFORCED,
                    requires_dual_custody=False,
                    rationale=f"Hourly autonomous execution quota exhausted ({hourly_count}/{policy.max_autonomous_actions_per_hour})",
                    action_id=action.action_id,
                )

            # All policy checks cleared for autonomous execution
            return PolicyEvaluationResult(
                decision=PolicyEvaluationDecision.ALLOW_AUTONOMOUS,
                applied_mode=ProtectionMode.ENFORCED,
                requires_dual_custody=False,
                rationale="Policy evaluated: autonomous execution authorized under ENFORCED mode",
                action_id=action.action_id,
            )

        # Fallback conservative gating
        return PolicyEvaluationResult(
            decision=PolicyEvaluationDecision.REQUIRE_APPROVAL,
            applied_mode=policy.default_mode,
            requires_dual_custody=True,
            rationale="Default safety fallback: requiring human approval",
            action_id=action.action_id,
        )

    def _load_tenant_policy(self, tenant_id: str) -> TenantDefensePolicy:
        """
        Loads policy from database or returns mandatory default (OBSERVE).
        """
        row = (
            self.db.query(TenantDefensePolicyModel)
            .filter(TenantDefensePolicyModel.tenant_id == tenant_id)
            .first()
        )
        if not row:
            return TenantDefensePolicy(
                tenant_id=tenant_id,
                default_mode=ProtectionMode.OBSERVE,
                is_active=True,
            )

        config = row.configuration or {}
        try:
            default_mode = ProtectionMode(row.default_mode.lower())
        except ValueError:
            default_mode = ProtectionMode.OBSERVE

        allowed = [
            ActionType(a) for a in config.get(
                "allowed_autonomous_actions",
                [ActionType.TEMPORARY_RATE_LIMIT.value, ActionType.TEMPORARY_IP_BLOCK.value]
            )
            if a in (ActionType.TEMPORARY_RATE_LIMIT.value, ActionType.TEMPORARY_IP_BLOCK.value)
        ]

        return TenantDefensePolicy(
            tenant_id=tenant_id,
            default_mode=default_mode,
            is_active=row.is_active,
            allowed_autonomous_actions=allowed,
            max_autonomous_ttl_seconds=int(config.get("max_autonomous_ttl_seconds", 3600)),
            max_autonomous_actions_per_hour=int(config.get("max_autonomous_actions_per_hour", 10)),
            action_overrides=config.get("action_overrides", {}),
        )

    def _get_recent_autonomous_action_count(self, tenant_id: str) -> int:
        """
        Counts executed autonomous actions within the past 1 hour for this tenant.
        """
        one_hour_ago = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)
        count = (
            self.db.query(DefenseActionModel)
            .filter(
                DefenseActionModel.tenant_id == tenant_id,
                DefenseActionModel.protection_mode == ProtectionMode.ENFORCED.value,
                DefenseActionModel.status.in_([
                    ActionStatus.EXECUTING.value,
                    ActionStatus.VERIFYING.value,
                    ActionStatus.VERIFIED_ACTIVE.value,
                ]),
                DefenseActionModel.executed_at >= one_hour_ago,
            )
            .count()
        )
        return count
