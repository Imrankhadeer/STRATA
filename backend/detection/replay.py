"""
Detector Candidate Replay Validation Engine for CYBER ENGINE.

Validates candidate declarative rules against standard incident evaluation suites:
1. Replays suspicious scenarios (true attack vectors) and benign lookalikes.
2. Computes TP, FP, TN, FN, precision, recall, and F1.
3. Enforces strict zero-false-positive validation gate before promotion eligibility.
4. Requires explicit human/policy approval record before activation.
5. Invariant: Detection on the Fast Track remains 100% deterministic (0 LLM calls per event).
"""

from typing import Dict, List, Optional
import datetime
import logging

logger = logging.getLogger("cyber_engine.replay")

from backend.schemas.rules import (
    DeclarativeRule,
    ReplayValidationMetrics,
    ApprovalRecord,
    CrossServiceRuleParameters,
    BruteForceRuleParameters,
)
from backend.investigation.evaluation_suite import (
    EvaluationScenario,
    build_evaluation_suite,
)
from backend.detection.baseline import BaseDetector, BruteForceLoginDetector
from backend.detection.correlation import CrossServiceExfiltrationDetector


class ReplayValidationEngine:
    """
    Evaluates candidate declarative rules by replaying reproducible scenario suites.
    """

    def __init__(self, scenarios: Optional[Dict[str, EvaluationScenario]] = None):
        self.scenarios = scenarios or build_evaluation_suite()

    def instantiate_detector(self, rule: DeclarativeRule) -> BaseDetector:
        """
        Instantiates the deterministic detector with the rule's validated declarative parameters.
        Supports both generic declarative rules and legacy detector configurations.
        No dynamic code evaluation or script execution occurs.
        """
        if rule.parameters and rule.parameters.get("rule_type") in ("threshold", "sequence"):
            from backend.schemas.declarative_spec import GenericDeclarativeRuleDefinition
            from backend.detection.generic_evaluator import GenericDeclarativeEvaluator
            from backend.detection.state_store import InMemoryCorrelationStateStore, RedisCorrelationStateStore
            from backend.config import settings

            state_store = None
            is_prod = settings.ENVIRONMENT.lower() in ("production", "staging")
            redis_mandatory = settings.REDIS_REQUIRED or is_prod or (settings.WORKERS > 1)

            if getattr(settings, "REDIS_URL", None):
                try:
                    candidate_store = RedisCorrelationStateStore(
                        settings.REDIS_URL,
                        socket_timeout=settings.REDIS_STATE_TIMEOUT_MS / 1000.0,
                    )
                    # Explicitly ping Redis to verify live connectivity
                    candidate_store.client.ping()
                    state_store = candidate_store
                except Exception as e:
                    if redis_mandatory:
                        raise RuntimeError(
                            f"Fatal: Failed initializing required RedisCorrelationStateStore in {settings.ENVIRONMENT} "
                            f"(REDIS_REQUIRED={settings.REDIS_REQUIRED}, WORKERS={settings.WORKERS}): {e}"
                        ) from e
                    logger.warning(
                        "Could not initialize RedisCorrelationStateStore (%s); using in-memory store in %s",
                        e,
                        settings.ENVIRONMENT,
                    )
                    state_store = InMemoryCorrelationStateStore()
            elif redis_mandatory:
                raise RuntimeError(
                    f"Fatal: Redis is required in {settings.ENVIRONMENT} mode (REDIS_REQUIRED={settings.REDIS_REQUIRED}, "
                    f"WORKERS={settings.WORKERS}), but REDIS_URL is not configured."
                )
            else:
                state_store = InMemoryCorrelationStateStore()

            spec = GenericDeclarativeRuleDefinition(**rule.parameters)
            return GenericDeclarativeEvaluator(
                rule_id=rule.rule_id,
                version=rule.version,
                title=rule.title,
                description=rule.description,
                spec=spec,
                state_store=state_store,
            )
        elif rule.target_detector == "detector.cross_service.exfiltration":
            params = CrossServiceRuleParameters(**rule.parameters)
            return CrossServiceExfiltrationDetector(
                time_window_seconds=params.time_window_seconds,
                bulk_row_threshold=params.bulk_row_threshold,
                sensitive_tables=frozenset(params.sensitive_tables),
                internal_prefixes=tuple(params.internal_prefixes),
            )
        elif rule.target_detector == "detector.auth.failed_threshold":
            params = BruteForceRuleParameters(**rule.parameters)
            return BruteForceLoginDetector(
                failure_threshold=params.failure_threshold,
            )
        else:
            raise ValueError(f"Unknown target detector: '{rule.target_detector}'")

    def validate_rule(self, rule: DeclarativeRule) -> ReplayValidationMetrics:
        """
        Replays all scenarios against the candidate detector configuration.
        Computes performance metrics and determines promotion eligibility.
        """
        detector = self.instantiate_detector(rule)

        tp = 0
        fp = 0
        tn = 0
        fn = 0
        failure_reasons: List[str] = []

        # Only evaluate scenarios relevant to this detector type
        relevant_scenarios = [
            s for s in self.scenarios.values()
            if s.expected_detector_id == rule.target_detector or not s.ground_truth_threat
        ]

        for sc in relevant_scenarios:
            if hasattr(detector, "reset"):
                detector.reset()

            triggered = False
            for event in sc.events:
                finding = detector.evaluate(event)
                if finding is not None:
                    triggered = True
                    break

            if sc.ground_truth_threat:
                if triggered:
                    tp += 1
                else:
                    fn += 1
                    failure_reasons.append(
                        f"Missed true attack in scenario '{sc.name}' ({sc.scenario_id})"
                    )
            else:
                if triggered:
                    fp += 1
                    failure_reasons.append(
                        f"False positive alert on benign scenario '{sc.name}' ({sc.scenario_id})"
                    )
                else:
                    tn += 1

        total = tp + fp + tn + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0 if fp == 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 1.0 if fn == 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 0.0

        # Strict Validation Gate Criteria:
        # 1. Zero False Positives on benign scenarios (fp == 0)
        # 2. Perfect or acceptable recall on known attacks (recall >= 1.0 on test suite)
        passed = (fp == 0) and (recall >= 1.0) and (tp > 0 or not any(s.ground_truth_threat for s in relevant_scenarios))

        metrics = ReplayValidationMetrics(
            scenarios_evaluated=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 3),
            recall=round(recall, 3),
            f1_score=round(f1, 3),
            accuracy=round(accuracy, 3),
            passed_validation=passed,
            failure_reasons=failure_reasons,
        )

        rule.validation_metrics = metrics
        if passed:
            rule.status = "validated"
        else:
            rule.status = "rejected"

        return metrics

    def approve_candidate_rule(
        self,
        rule: DeclarativeRule,
        decided_by: str,
        rationale: str,
        decision: str = "approved",
    ) -> DeclarativeRule:
        """
        Human / Policy Approval Gate.
        A rule CANNOT be approved unless it has successfully passed replay validation.
        """
        if rule.status not in ("validated", "approved"):
            raise ValueError(
                f"Rule '{rule.rule_id}' cannot be approved because its current status is '{rule.status}'. "
                "Only rules that passed replay validation (status='validated') are eligible for approval."
            )

        if decision == "approved":
            rule.status = "approved"
        else:
            rule.status = "rejected"

        rule.approval = ApprovalRecord(
            decision="approved" if decision == "approved" else "rejected",
            decided_by=decided_by,
            rationale=rationale,
        )
        return rule

    def activate_rule(self, rule: DeclarativeRule) -> DeclarativeRule:
        """
        Promotes an approved rule to active status in the fast-track rule registry.
        """
        if rule.status != "approved":
            raise ValueError(
                f"Rule '{rule.rule_id}' cannot be activated because its status is '{rule.status}'. "
                "Explicit human approval (status='approved') is required before activation."
            )

        rule.status = "active"
        return rule

    def disable_rule(
        self,
        rule: DeclarativeRule,
        disabled_by: str,
        reason: str,
    ) -> DeclarativeRule:
        """
        Disables an active or approved rule, withdrawing it from runtime evaluation.
        """
        if rule.status not in ("active", "approved"):
            raise ValueError(
                f"Rule '{rule.rule_id}' cannot be disabled because its current status is '{rule.status}'."
            )
        rule.status = "disabled"
        return rule

