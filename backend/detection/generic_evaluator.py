"""
Generic Declarative Detection Evaluator for CYBER ENGINE.

An independent, reusable, deterministic evaluator implementing the BaseDetector interface.
Evaluates:
- Threshold-based single-stream aggregation rules.
- Multi-stage, cross-service sequence correlation rules within sliding trace windows.

Safety Invariants:
1. Zero dynamic code execution (no eval, exec, import, or unverified expressions).
2. Pure mathematical and string operator allowlist.
3. Bounded in-memory state with strict LRU and time-window eviction.
4. Tenant boundary isolation across all tracking windows.
5. Deterministic execution (<10ms, 0 LLM inference calls).
"""

from typing import Dict, List, Optional, Set, Tuple, Any, Union
import datetime
import logging
from collections import OrderedDict

from backend.detection.baseline import BaseDetector, Finding
from backend.schemas.events import CanonicalEvent
from backend.schemas.declarative_spec import (
    GenericDeclarativeRuleDefinition,
    FieldCondition,
    SequenceStage,
)
from backend.detection.state_store import (
    BaseCorrelationStore,
    InMemoryCorrelationStateStore,
    RedisCorrelationStateStore,
)

logger = logging.getLogger("cyber_engine.generic_evaluator")


def _get_nested_field(event: CanonicalEvent, field_path: str) -> Any:
    """
    Safely retrieves a field value from a CanonicalEvent using dot-notation.
    Supports top-level event fields and nested attributes / provenance dicts.
    Fails closed (returns None) on missing, unindexed, or non-dict paths.
    """
    parts = field_path.split(".")
    top_key = parts[0]

    # Resolve top-level field with common telemetry fallbacks
    if hasattr(event, top_key):
        val = getattr(event, top_key)
        if (val is None or val == "") and top_key == "source_resource":
            val = getattr(event, "attributes", {}).get("client_ip")
        elif (val is None or val == "") and top_key == "target_resource":
            val = getattr(event, "attributes", {}).get("endpoint")
    elif top_key in ("attributes", "provenance"):
        val = getattr(event, top_key, {})
    else:
        return None

    # Resolve nested keys
    for p in parts[1:]:
        if isinstance(val, dict):
            val = val.get(p)
        else:
            return None
    return val


def _evaluate_condition(event: CanonicalEvent, condition: FieldCondition) -> bool:
    """
    Evaluates a single FieldCondition deterministically against an event.
    Strictly uses the operator allowlist with type-safe comparisons.
    """
    val = _get_nested_field(event, condition.field)
    op = condition.operator

    # Exists check
    if op == "exists":
        return val is not None

    if val is None:
        return False

    # Boolean checks
    if op == "is_true":
        return val is True or val == "true" or val == 1
    if op == "is_false":
        return val is False or val == "false" or val == 0

    # Equality checks
    if op == "equals":
        return val == condition.value
    if op == "not_equals":
        return val != condition.value

    # Set membership checks
    if op == "in":
        if condition.values is None:
            return False
        return val in condition.values
    if op == "not_in":
        if condition.values is None:
            return False
        return val not in condition.values

    # String operations (requires string val)
    if not isinstance(val, str):
        val_str = str(val)
    else:
        val_str = val

    if op == "starts_with":
        target = str(condition.value) if condition.value is not None else ""
        return val_str.startswith(target)
    if op == "starts_with_any":
        if not condition.values:
            return False
        return any(val_str.startswith(str(prefix)) for prefix in condition.values)
    if op == "ends_with":
        target = str(condition.value) if condition.value is not None else ""
        return val_str.endswith(target)
    if op == "contains":
        target = str(condition.value) if condition.value is not None else ""
        return target in val_str

    # Numerical comparisons
    try:
        num_val = float(val)
        num_target = float(condition.value) if condition.value is not None else 0.0
    except (ValueError, TypeError):
        return False

    if op == "gt":
        return num_val > num_target
    if op == "gte":
        return num_val >= num_target
    if op == "lt":
        return num_val < num_target
    if op == "lte":
        return num_val <= num_target

    return False


class _TraceSequenceState:
    """
    State window for a single group key (e.g. tenant_id + trace_id) in sequence correlation.
    """
    __slots__ = (
        "first_seen", "last_seen", "stage_matches",
        "seen_event_ids", "finding_emitted"
    )

    def __init__(self, timestamp: datetime.datetime):
        self.first_seen: datetime.datetime = timestamp
        self.last_seen: datetime.datetime = timestamp
        # stage_id -> list of matching CanonicalEvents
        self.stage_matches: Dict[str, List[CanonicalEvent]] = {}
        self.seen_event_ids: Set[str] = set()
        self.finding_emitted: bool = False

    def update_time(self, ts: datetime.datetime):
        if ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts


class _ThresholdCounterState:
    """
    State window for a single group key (e.g. tenant_id + source_resource) in threshold counting.
    """
    __slots__ = (
        "first_seen", "last_seen", "count", "aggregated_value",
        "seen_event_ids", "finding_emitted", "matching_events"
    )

    def __init__(self, timestamp: datetime.datetime):
        self.first_seen: datetime.datetime = timestamp
        self.last_seen: datetime.datetime = timestamp
        self.count: int = 0
        self.aggregated_value: float = 0.0
        self.seen_event_ids: Set[str] = set()
        self.finding_emitted: bool = False
        self.matching_events: List[CanonicalEvent] = []

    def update_time(self, ts: datetime.datetime):
        if ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts


class GenericDeclarativeEvaluator(BaseDetector):
    """
    Generic, deterministic detection evaluator configured by a GenericDeclarativeRuleDefinition.
    Evaluates both threshold aggregation rules and multi-stage cross-service sequences.
    """

    def __init__(
        self,
        rule_id: str,
        version: Union[int, str],
        title: str,
        description: str,
        spec: GenericDeclarativeRuleDefinition,
        severity: str = "high",
        max_tracked_keys: int = 10_000,
        max_future_skew_seconds: float = 300.0,
        max_late_arrival_seconds: float = 86400.0,
        state_store: Optional[BaseCorrelationStore] = None,
    ):
        self.detector_id = rule_id
        self.detector_version = str(version)
        self.title = title
        self.description = description
        self.spec = spec
        self.severity = getattr(spec, "severity", None) or severity
        self.max_tracked_keys = max_tracked_keys
        self.max_future_skew_seconds = max_future_skew_seconds
        self.max_late_arrival_seconds = max_late_arrival_seconds
        self.time_window = datetime.timedelta(seconds=spec.window_seconds)

        # Pluggable state store (defaults to thread-safe InMemory store for local execution)
        self.state_store: BaseCorrelationStore = state_store or InMemoryCorrelationStateStore(
            max_tracked_keys=max_tracked_keys
        )

        # Monotonic time watermark per tenant to prevent future-timestamp cache eviction (Hypothesis 1)
        self._tenant_watermarks: Dict[str, datetime.datetime] = {}

    @property
    def _sequence_windows(self):
        """Backward-compatibility proxy for test inspections."""
        if hasattr(self.state_store, "_sequence_windows"):
            return self.state_store._sequence_windows
        return {}

    @property
    def _threshold_windows(self):
        """Backward-compatibility proxy for test inspections."""
        if hasattr(self.state_store, "_threshold_windows"):
            return self.state_store._threshold_windows
        return {}

    @property
    def _emitted_keys(self):
        """Backward-compatibility proxy for test inspections."""
        if hasattr(self.state_store, "_emitted_keys"):
            return self.state_store._emitted_keys
        return set()

    def reset(self) -> None:
        """Reset internal evaluator state (for test isolation and clean-room testing)."""
        self._tenant_watermarks.clear()
        self.state_store.reset()

    def _extract_group_key(self, event: CanonicalEvent) -> Optional[Tuple[str, ...]]:
        """
        Extracts the tuple group key from the event based on spec.group_by.
        If any required group_by field is missing or None on the event, returns None (fails closed).
        """
        key_parts = []
        for f in self.spec.group_by:
            val = _get_nested_field(event, f)
            if val is None or val == "":
                return None
            key_parts.append(str(val))
        return tuple(key_parts)

    def _match_sequence_stage(self, event: CanonicalEvent) -> Optional[str]:
        """
        Checks which stage of the sequence rule this event satisfies.
        Supports both 'all' (conjunctive) and 'any' (disjunctive) condition matching.
        """
        if not self.spec.sequence_stages:
            return None

        for stage in self.spec.sequence_stages:
            if stage.service_id and event.service_id != stage.service_id:
                continue
            if not stage.conditions:
                return stage.stage_id
            match_mode = getattr(stage, "match_mode", "all")
            if match_mode == "any":
                matched = any(_evaluate_condition(event, cond) for cond in stage.conditions)
            else:
                matched = all(_evaluate_condition(event, cond) for cond in stage.conditions)
            if matched:
                return stage.stage_id

        return None

    def evaluate(self, event: CanonicalEvent) -> Optional[Finding]:
        """
        Evaluates an event deterministically against the declarative rule specification.
        Returns a Finding if the rule triggers, else None.
        Enforces clock-skew tolerances and tenant-isolated monotonic eviction (Hypothesis 1).
        Delegates state persistence to the pluggable BaseCorrelationStore (Hypothesis 2).
        """
        tenant_id = event.tenant_id or "default"

        # Standardize timestamp to UTC timezone
        ev_ts = event.timestamp
        if ev_ts.tzinfo is None:
            ev_ts = ev_ts.replace(tzinfo=datetime.timezone.utc)

        # 1. Monotonic tenant watermark tracking and clock-skew defenses
        watermark = self._tenant_watermarks.get(tenant_id)
        if watermark is None:
            self._tenant_watermarks[tenant_id] = ev_ts
            effective_watermark = ev_ts
        else:
            if watermark.tzinfo is None:
                watermark = watermark.replace(tzinfo=datetime.timezone.utc)
                self._tenant_watermarks[tenant_id] = watermark

            future_skew = (ev_ts - watermark).total_seconds()
            if future_skew > self.max_future_skew_seconds:
                reason = f"future_timestamp_skew_exceeded: jumped {future_skew:.1f}s into the future (max {self.max_future_skew_seconds}s)"
                if not hasattr(event, "attributes") or event.attributes is None:
                    event.attributes = {}
                event.attributes["_skew_warning"] = reason
                logger.warning("Tenant '%s' event '%s' rejected for future skew: %s", tenant_id, event.event_id, reason)
                return None

            late_skew = (watermark - ev_ts).total_seconds()
            if late_skew > self.max_late_arrival_seconds:
                reason = f"late_event_outside_retention: {late_skew:.1f}s older than active retention (max {self.max_late_arrival_seconds}s)"
                if not hasattr(event, "attributes") or event.attributes is None:
                    event.attributes = {}
                event.attributes["_skew_warning"] = reason
                logger.warning("Tenant '%s' event '%s' dropped for late arrival: %s", tenant_id, event.event_id, reason)
                return None

            if ev_ts > watermark:
                self._tenant_watermarks[tenant_id] = ev_ts
            effective_watermark = self._tenant_watermarks[tenant_id]

        # 2. Extract group key
        group_key = self._extract_group_key(event)
        if not group_key:
            return None

        # 3. Evaluate Rule Type via Pluggable State Store
        if self.spec.rule_type == "threshold":
            if self.spec.conditions:
                for cond in self.spec.conditions:
                    if not _evaluate_condition(event, cond):
                        return None
            return self.state_store.evaluate_threshold(
                rule_id=self.detector_id,
                version=self.detector_version,
                title=self.title,
                description=self.description,
                spec=self.spec,
                event=event,
                group_key=group_key,
                effective_watermark=effective_watermark,
            )
        elif self.spec.rule_type == "sequence":
            matched_stage_id = self._match_sequence_stage(event)
            if not matched_stage_id:
                return None
            return self.state_store.evaluate_sequence(
                rule_id=self.detector_id,
                version=self.detector_version,
                title=self.title,
                description=self.description,
                spec=self.spec,
                event=event,
                group_key=group_key,
                matched_stage_id=matched_stage_id,
                effective_watermark=effective_watermark,
            )

        return None



