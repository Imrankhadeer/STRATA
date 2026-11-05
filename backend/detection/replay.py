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
        is_legacy_exfil = (
            rule.target_detector in ("detector.cross_service.exfiltration", "detector.exfiltration.cross_service")
            and not (rule.parameters and rule.parameters.get("rule_type") in ("threshold", "sequence"))
        )
        is_legacy_auth = (
            rule.target_detector in ("detector.auth.failed_threshold", "detector.auth.brute_force", "detector.auth.password_spray")
            and not (rule.parameters and rule.parameters.get("rule_type") in ("threshold", "sequence"))
        )

        if is_legacy_exfil:
            p = dict(rule.parameters or {})
            if "bulk_row_threshold" not in p:
                p["bulk_row_threshold"] = int(p.get("row_threshold") or p.get("max_rows") or 1000)
            if "time_window_seconds" not in p:
                p["time_window_seconds"] = float(p.get("window_seconds") or 300.0)
            params = CrossServiceRuleParameters(**p)
            return CrossServiceExfiltrationDetector(
                time_window_seconds=params.time_window_seconds,
                bulk_row_threshold=params.bulk_row_threshold,
                sensitive_tables=frozenset(params.sensitive_tables),
                internal_prefixes=tuple(params.internal_prefixes),
            )
        elif is_legacy_auth:
            p = dict(rule.parameters or {})
            if "failure_threshold" not in p:
                f_val = p.get("failure_count") or p.get("count") or (p.get("threshold", {}).get("value") if isinstance(p.get("threshold"), dict) else p.get("threshold")) or 5
                p["failure_threshold"] = int(f_val)
            if "window_seconds" not in p:
                p["window_seconds"] = float(p.get("time_window_seconds") or 60.0)
            params = BruteForceRuleParameters(**p)
            return BruteForceLoginDetector(
                failure_threshold=params.failure_threshold,
            )
        else:
            # Generic declarative evaluation (supports detector.deep_track.promoted, generic.declarative, and all custom/promoted rules)
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

            norm_params = dict(rule.parameters or {})
            if "rule_type" not in norm_params:
                norm_params["rule_type"] = norm_params.get("type") or (
                    "sequence" if "sequence_stages" in norm_params or "stages" in norm_params else "threshold"
                )

            # Ensure threshold specification has required 'value' field if rule_type is threshold
            if norm_params["rule_type"] == "threshold":
                raw_thresh = norm_params.get("threshold")
                val = None
                metric = "count"
                op = "gte"
                if isinstance(raw_thresh, dict):
                    val = (
                        raw_thresh.get("value")
                        if raw_thresh.get("value") is not None
                        else (
                            raw_thresh.get("count")
                            or raw_thresh.get("failure_count")
                            or raw_thresh.get("failure_threshold")
                            or raw_thresh.get("row_threshold")
                            or raw_thresh.get("max_rows")
                        )
                    )
                    metric = raw_thresh.get("metric", "count")
                    op = raw_thresh.get("operator", "gte")
                elif isinstance(raw_thresh, (int, float)):
                    val = raw_thresh
                else:
                    val = (
                        norm_params.get("failure_threshold")
                        or norm_params.get("failure_count")
                        or norm_params.get("count")
                        or norm_params.get("row_threshold")
                        or norm_params.get("max_rows")
                        or norm_params.get("value")
                    )

                try:
                    val = float(val) if val is not None else 5.0
                except (ValueError, TypeError):
                    val = 5.0

                norm_params["threshold"] = {
                    "metric": metric if metric in ("count", "attribute_sum", "attribute_max") else "count",
                    "operator": op if op in ("gte", "gt", "lte", "lt", "equals") else "gte",
                    "value": val,
                }

                if not norm_params.get("conditions"):
                    if "event_type" in norm_params:
                        norm_params["conditions"] = [{"field": "event_type", "operator": "contains", "value": str(norm_params["event_type"])}]
                    elif rule.target_detector in ("detector.auth.failed_threshold", "detector.auth.brute_force"):
                        norm_params["conditions"] = [{"field": "event_type", "operator": "contains", "value": "login_failed"}]
                    elif rule.target_detector in ("detector.cross_service.exfiltration", "detector.exfiltration.cross_service"):
                        norm_params["conditions"] = [{"field": "event_type", "operator": "contains", "value": "exfiltration"}]
                    else:
                        norm_params["conditions"] = [{"field": "event_type", "operator": "exists"}]

            if "sequence_stages" not in norm_params and "stages" in norm_params:
                norm_params["sequence_stages"] = norm_params["stages"]

            if "sequence_stages" in norm_params and isinstance(norm_params["sequence_stages"], list):
                raw_stages = norm_params["sequence_stages"]
                normalized_stages = []
                for idx, st in enumerate(raw_stages):
                    if isinstance(st, str):
                        clean_svc = st.replace("-", "_").replace(".", "_")
                        normalized_stages.append({
                            "stage_id": f"stage_{idx}_{clean_svc}",
                            "service_id": st,
                        })
                    elif isinstance(st, dict):
                        st_copy = dict(st)
                        if "stage_id" not in st_copy:
                            svc = st_copy.get("service_id", f"stage_{idx}")
                            clean_svc = str(svc).replace("-", "_").replace(".", "_")
                            st_copy["stage_id"] = f"stage_{idx}_{clean_svc}"
                        normalized_stages.append(st_copy)
                    else:
                        normalized_stages.append(st)
                norm_params["sequence_stages"] = normalized_stages

            # Infer evaluation_target_detector if not explicitly provided
            if "evaluation_target_detector" not in norm_params:
                t_lower = (rule.target_detector or "").lower()
                title_lower = (rule.title or "").lower()
                if "auth" in t_lower or "brute" in t_lower or "login" in title_lower:
                    norm_params["evaluation_target_detector"] = "detector.auth.failed_threshold"
                elif "exfil" in t_lower or "cross" in t_lower or "database" in title_lower or "export" in title_lower:
                    norm_params["evaluation_target_detector"] = "detector.cross_service.exfiltration"

            spec = GenericDeclarativeRuleDefinition(**norm_params)
            return GenericDeclarativeEvaluator(
                rule_id=rule.rule_id,
                version=rule.version,
                title=rule.title,
                description=rule.description,
                spec=spec,
                state_store=state_store,
            )

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
        # For detector-specific rules (even if parameterized declaratively), restrict to that detector
        evaluation_target = (rule.parameters or {}).get("evaluation_target_detector")
        is_generic_unbound = (
            rule.target_detector in ("detector.deep_track.promoted", "generic.declarative")
            and evaluation_target is None
        )
        scenario_target = evaluation_target or rule.target_detector
        relevant_scenarios = [
            s for s in self.scenarios.values()
            if is_generic_unbound or s.expected_detector_id == scenario_target or not s.ground_truth_threat
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

