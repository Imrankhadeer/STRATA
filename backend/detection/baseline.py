from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Set
from pydantic import BaseModel, Field
import uuid
import datetime
from backend.schemas.events import CanonicalEvent


class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tenant_id: str
    detector_id: str
    detector_version: str
    title: str
    severity: str
    confidence: str = "medium"
    description: str
    event_id: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))


class BaseDetector(ABC):
    """
    Abstract interface for fast-path continuous protection detectors.
    Completely decoupled from AI providers and capable of standalone execution.
    """
    detector_id: str
    detector_version: str
    description: str

    @abstractmethod
    def evaluate(self, event: CanonicalEvent) -> Optional[Finding]:
        """
        Evaluates a single canonical event in the fast path.
        Returns a Finding if a rule/anomaly triggers, else None.
        """
    def reset(self) -> None:
        """Reset internal detector state (used for testing and test isolation)."""
        pass


class BruteForceLoginDetector(BaseDetector):
    """
    Baseline deterministic detector that detects failed login threshold indicators
    or high-risk authentication abuse signals within fast continuous telemetry.
    """
    detector_id = "detector.auth.failed_threshold"
    detector_version = "1.0.0"
    description = "Detects repetitive login failures or suspicious brute-force attempts"

    def __init__(self, failure_threshold: int = 5):
        self.failure_threshold = failure_threshold
        # In-memory fast path tracking for demonstration/baseline
        self._failure_counts: Dict[str, int] = {}
        self._seen_event_ids: Set[str] = set()

    def reset(self) -> None:
        self._failure_counts.clear()
        self._seen_event_ids.clear()

    def evaluate(self, event: CanonicalEvent) -> Optional[Finding]:
        if event.event_type != "auth.login_failed":
            return None

        # Ignore duplicate event IDs
        if event.event_id in self._seen_event_ids:
            return None
        self._seen_event_ids.add(event.event_id)

        actor = event.source_resource or event.attributes.get("client_ip") or "unknown_actor"
        key = f"{event.tenant_id}:{actor}"
        self._failure_counts[key] = self._failure_counts.get(key, 0) + 1

        attempts = self._failure_counts[key]
        if attempts >= self.failure_threshold:
            return Finding(
                tenant_id=event.tenant_id or "default",
                detector_id=self.detector_id,
                detector_version=self.detector_version,
                title=f"Potential Brute-force Attack from {actor}",
                severity="high" if attempts > 10 else "medium",
                confidence="high",
                description=f"Actor '{actor}' exceeded failed login threshold with {attempts} consecutive attempts.",
                event_id=event.event_id,
                evidence={
                    "actor": actor,
                    "attempt_count": attempts,
                    "target_resource": event.target_resource,
                    "trace_id": event.trace_id,
                }
            )
        return None
