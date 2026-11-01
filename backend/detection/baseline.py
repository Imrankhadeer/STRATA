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
    Baseline deterministic detector that detects failed login threshold indicators,
    brute-force attacks, and password spraying within rolling sliding windows.
    """
    detector_id = "detector.auth.failed_threshold"
    detector_version = "1.0.0"
    description = "Detects repetitive login failures, brute-force attempts, and password spraying"

    def __init__(
        self,
        failure_threshold: int = 5,
        window_seconds: float = 300.0,
        spray_threshold: int = 5,
    ):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self.spray_threshold = spray_threshold
        # Sliding windows: key -> list of (timestamp_float, event_id)
        self._actor_windows: Dict[str, List[tuple[float, str]]] = {}
        # User windows for spray tracking: key -> list of (timestamp_float, event_id, actor)
        self._user_windows: Dict[str, List[tuple[float, str, str]]] = {}
        self._seen_event_ids: Set[str] = set()

    def reset(self) -> None:
        self._actor_windows.clear()
        self._user_windows.clear()
        self._seen_event_ids.clear()

    def evaluate(self, event: CanonicalEvent) -> Optional[Finding]:
        if event.event_type != "auth.login_failed":
            return None

        # Ignore duplicate event IDs
        if event.event_id in self._seen_event_ids:
            return None
        self._seen_event_ids.add(event.event_id)

        ev_time = event.timestamp.timestamp()
        cutoff = ev_time - self.window_seconds

        actor = event.source_resource or (event.attributes and event.attributes.get("client_ip")) or "unknown_actor"
        tenant = event.tenant_id or "default"
        actor_key = f"{tenant}:{actor}"

        # 1. Update and prune actor sliding window
        window = self._actor_windows.get(actor_key, [])
        window = [item for item in window if item[0] >= cutoff]
        window.append((ev_time, event.event_id))
        self._actor_windows[actor_key] = window

        attempts = len(window)

        # 2. Check for Password Spraying (multiple distinct IPs targeting same username)
        username = None
        if event.attributes and isinstance(event.attributes, dict):
            username = event.attributes.get("username") or event.attributes.get("user")
        if not username and event.target_resource and not event.target_resource.startswith("/"):
            username = event.target_resource

        if username:
            user_key = f"{tenant}:{username}"
            u_window = self._user_windows.get(user_key, [])
            u_window = [item for item in u_window if item[0] >= cutoff]
            u_window.append((ev_time, event.event_id, actor))
            self._user_windows[user_key] = u_window

            distinct_actors = {item[2] for item in u_window if item[2] != "unknown_actor"}
            if len(distinct_actors) >= self.spray_threshold and actor != "unknown_actor":
                return Finding(
                    tenant_id=tenant,
                    detector_id="detector.auth.password_spray",
                    detector_version=self.detector_version,
                    title=f"Potential Password Spraying Attack targeting {username}",
                    severity="high",
                    confidence="high",
                    description=f"User account '{username}' targeted by {len(distinct_actors)} distinct sources within {self.window_seconds}s.",
                    event_id=event.event_id,
                    evidence={
                        "target_user": username,
                        "distinct_sources_count": len(distinct_actors),
                        "sources": sorted(list(distinct_actors))[:10],
                        "window_seconds": self.window_seconds,
                    },
                )

        # 3. Standard Brute Force / Failed Login Threshold
        if attempts >= self.failure_threshold:
            return Finding(
                tenant_id=tenant,
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
                    "window_seconds": self.window_seconds,
                },
            )

        return None
