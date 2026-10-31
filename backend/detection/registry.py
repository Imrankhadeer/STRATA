"""
Runtime Rule Registry for Dynamic Fast Track Threat Detection.

Responsibilities:
1. Loads approved and activated declarative rules dynamically per tenant.
2. Evaluates active rules deterministically against incoming telemetry with 0 LLM cost.
3. Tags each generated finding with the specific rule_id and version responsible.
4. Caches active detector instances with safe TTL and immediate invalidation on lifecycle transitions.
5. Strictly enforces tenant scope (cross-tenant rules can never execute).
6. Preserves existing native detectors and coordinates coverage to avoid duplicate findings.
"""

import time
import logging
import threading
from typing import Dict, List, Optional, Tuple, Set
from sqlalchemy.orm import Session

from backend.models import DeclarativeRuleModel
from backend.schemas.events import CanonicalEvent
from backend.schemas.rules import (
    DeclarativeRule,
    ReplayValidationMetrics,
    ApprovalRecord,
)
from backend.detection.baseline import BaseDetector, Finding
from backend.detection.replay import ReplayValidationEngine

logger = logging.getLogger("cyber_engine.registry")


class RuntimeRuleRegistry:
    """
    In-memory, tenant-isolated cache and execution coordinator for active declarative rules.
    """

    def __init__(self, ttl_seconds: float = 10.0):
        self.ttl_seconds = ttl_seconds
        # tenant_id -> list of (DeclarativeRule, BaseDetector)
        self._cache: Dict[str, List[Tuple[DeclarativeRule, BaseDetector]]] = {}
        # tenant_id -> last refresh timestamp
        self._last_refresh: Dict[str, float] = {}
        self._engine = ReplayValidationEngine()
        self._lock = threading.RLock()

    def invalidate(self, tenant_id: Optional[str] = None) -> None:
        """
        Forces immediate cache eviction for a tenant or globally.
        Called immediately on rule activation, disablement, or rollback to guarantee
        sub-millisecond runtime visibility without application restart.
        """
        with self._lock:
            if tenant_id:
                self._cache.pop(tenant_id, None)
                self._last_refresh.pop(tenant_id, None)
                logger.info("Runtime rule registry invalidated for tenant '%s'", tenant_id)
            else:
                self._cache.clear()
                self._last_refresh.clear()
                logger.info("Runtime rule registry completely flushed")

    def get_active_detectors(
        self, tenant_id: str, db: Session
    ) -> List[Tuple[DeclarativeRule, BaseDetector]]:
        """
        Retrieves instantiated active detectors for a specific tenant.
        Enforces tenant boundary isolation and loads only rules where status == 'active'.
        Thread-safe under concurrent ingestion and rule updates.
        """
        with self._lock:
            now = time.time()
            last = self._last_refresh.get(tenant_id, 0.0)

            if tenant_id in self._cache and (now - last) < self.ttl_seconds:
                return self._cache[tenant_id]

            # Query database for rules belonging STRICTLY to this tenant with active status
            db_rules = (
                db.query(DeclarativeRuleModel)
                .filter(
                    DeclarativeRuleModel.tenant_id == tenant_id,
                    DeclarativeRuleModel.status == "active",
                )
                .all()
            )

            detectors: List[Tuple[DeclarativeRule, BaseDetector]] = []
            for r in db_rules:
                try:
                    rule_schema = DeclarativeRule(
                        rule_id=r.rule_id,
                        tenant_id=r.tenant_id,
                        version=r.version,
                        target_detector=r.target_detector,
                        title=r.title,
                        description=r.description,
                        parameters=r.parameters,
                        status=r.status,
                        created_at=r.created_at,
                        validation_metrics=ReplayValidationMetrics(**r.validation_metrics)
                        if r.validation_metrics
                        else None,
                        approval=ApprovalRecord(**r.approval_metadata)
                        if r.approval_metadata
                        else None,
                    )
                    detector_inst = self._engine.instantiate_detector(rule_schema)
                    # Assign rule metadata to detector
                    detector_inst.detector_id = r.rule_id
                    detector_inst.detector_version = str(r.version)
                    detectors.append((rule_schema, detector_inst))
                except Exception as err:
                    logger.error(
                        "Failed to instantiate active rule '%s' (v%s) for tenant '%s': %s",
                        r.rule_id,
                        r.version,
                        tenant_id,
                        err,
                    )

            self._cache[tenant_id] = detectors
            self._last_refresh[tenant_id] = now
            logger.debug(
                "Refreshed %d active rule detector(s) for tenant '%s'",
                len(detectors),
                tenant_id,
            )
            return detectors

    def evaluate_active_rules(
        self, event: CanonicalEvent, db: Session
    ) -> Tuple[List[Finding], Set[str], str, Optional[str]]:
        """
        Evaluates incoming canonical event against active declarative rules for the event's tenant.
        Returns:
            - List of triggered Findings with rule_id and rule_version explicitly recorded.
            - Set of covered target detector families (to suppress conflicting/duplicate native alerts).
            - correlation_status: "ok" or "degraded".
            - correlation_error: error details if state-store or rule evaluation failed.
        """
        if not event.tenant_id:
            return [], set(), "ok", None

        active_items = self.get_active_detectors(event.tenant_id, db)
        findings: List[Finding] = []
        covered_families: Set[str] = set()
        correlation_status = "ok"
        correlation_error = None

        for rule_schema, detector in active_items:
            try:
                finding = detector.evaluate(event)
                # Successful evaluation: cover this family to avoid duplicate native alerts
                if rule_schema.target_detector:
                    covered_families.add(rule_schema.target_detector)

                if finding:
                    # Invariant: Record the rule ID and version responsible for each finding
                    finding.detector_id = rule_schema.rule_id
                    finding.detector_version = str(rule_schema.version)

                    # Preserve audit provenance in evidence
                    finding.evidence["rule_id"] = rule_schema.rule_id
                    finding.evidence["rule_version"] = rule_schema.version
                    finding.evidence["rule_title"] = rule_schema.title
                    finding.evidence["target_detector"] = rule_schema.target_detector

                    findings.append(finding)
            except Exception as e:
                logger.error("Error evaluating rule '%s': %s", rule_schema.rule_id, e)
                correlation_status = "degraded"
                correlation_error = f"Evaluation error in rule '{rule_schema.rule_id}': {e}"
                # Invariant: Do NOT cover this family if evaluation failed, ensuring
                # native baseline fallback detectors remain unsuppressed as a safety net.

        return findings, covered_families, correlation_status, correlation_error


# Global singleton instance
runtime_rule_registry = RuntimeRuleRegistry()

