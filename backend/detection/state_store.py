"""
Ternline Correlation State Store Architecture.

Provides pluggable correlation state persistence:
- BaseCorrelationStore: Abstract interface defining state operations.
- InMemoryCorrelationStateStore: Thread-safe, process-local state store with bounded cardinality.
- RedisCorrelationStateStore: Distributed, atomic Lua-scripted state store for multi-worker production.

Invariants:
1. Pure tenant-scoped keys to prevent cross-tenant state leakage.
2. Rule ID and version included in state keys to prevent cross-version collisions.
3. Server-time TTLs (never trusted client timestamps for state expiry).
4. Atomic updates via Redis Lua scripts to eliminate race conditions.
5. Deterministic deduplication of event IDs.
6. Explicit resource limits: max groups per tenant, max events per group, max candidates per stage, max seen event IDs.
7. Candidate preservation: multiple candidate events per sequence stage are fully retained.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Set, Tuple, Any, Union
import datetime
import hashlib
import json
import logging
import threading
from collections import OrderedDict, defaultdict

from backend.detection.baseline import Finding
from backend.schemas.events import CanonicalEvent
from backend.schemas.declarative_spec import (
    GenericDeclarativeRuleDefinition,
    FieldCondition,
    SequenceStage,
)

logger = logging.getLogger("cyber_engine.state_store")

# Default explicit resource bounds
DEFAULT_MAX_GROUPS_PER_TENANT = 5_000
DEFAULT_MAX_EVENTS_PER_THRESHOLD_GROUP = 500
DEFAULT_MAX_CANDIDATES_PER_STAGE = 20
DEFAULT_MAX_SEEN_EVENT_IDS = 1_000
DEFAULT_MAX_EVIDENCE_BYTES = 32_768


class RedisStateError(RuntimeError):
    """Raised when Redis distributed state operations fail."""
    pass


# -----------------------------------------------------------------------------
# Base Correlation Store Interface
# -----------------------------------------------------------------------------

class BaseCorrelationStore(ABC):
    """Abstract interface for threat correlation state storage."""

    @abstractmethod
    def evaluate_threshold(
        self,
        rule_id: str,
        version: str,
        title: str,
        description: str,
        spec: GenericDeclarativeRuleDefinition,
        event: CanonicalEvent,
        group_key: Tuple[str, ...],
        effective_watermark: datetime.datetime,
    ) -> Optional[Finding]:
        """Atomically evaluates threshold aggregation state and emits a Finding if triggered."""
        pass

    @abstractmethod
    def evaluate_sequence(
        self,
        rule_id: str,
        version: str,
        title: str,
        description: str,
        spec: GenericDeclarativeRuleDefinition,
        event: CanonicalEvent,
        group_key: Tuple[str, ...],
        matched_stage_id: str,
        effective_watermark: datetime.datetime,
    ) -> Optional[Finding]:
        """Atomically evaluates multi-stage sequence state and emits a Finding if completed."""
        pass

    @abstractmethod
    def reset(self) -> None:
        """Purges all correlation state."""
        pass

    @abstractmethod
    def get_health(self) -> Dict[str, Any]:
        """Returns health and operational metrics of the state store."""
        pass


# -----------------------------------------------------------------------------
# In-Memory Correlation State Store
# -----------------------------------------------------------------------------

class _ThresholdCounterState:
    def __init__(self, timestamp: datetime.datetime):
        self.count: int = 0
        self.aggregated_value: float = 0.0
        self.first_seen: datetime.datetime = timestamp
        self.last_seen: datetime.datetime = timestamp
        self.seen_event_ids: Set[str] = set()
        self.finding_emitted: bool = False

    def update_time(self, ts: datetime.datetime):
        if ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts


class _TraceSequenceState:
    def __init__(self, timestamp: datetime.datetime):
        self.first_seen: datetime.datetime = timestamp
        self.last_seen: datetime.datetime = timestamp
        self.stage_matches: Dict[str, List[CanonicalEvent]] = {}
        self.seen_event_ids: Set[str] = set()
        self.finding_emitted: bool = False

    def update_time(self, ts: datetime.datetime):
        if ts < self.first_seen:
            self.first_seen = ts
        if ts > self.last_seen:
            self.last_seen = ts


class InMemoryCorrelationStateStore(BaseCorrelationStore):
    """
    Thread-safe, process-local state store.
    Used for local development and single-worker execution with explicit resource bounds.
    """

    def __init__(
        self,
        max_tracked_keys: int = 10_000,
        max_groups_per_tenant: int = DEFAULT_MAX_GROUPS_PER_TENANT,
        max_events_per_group: int = DEFAULT_MAX_EVENTS_PER_THRESHOLD_GROUP,
        max_candidates_per_stage: int = DEFAULT_MAX_CANDIDATES_PER_STAGE,
        max_seen_event_ids: int = DEFAULT_MAX_SEEN_EVENT_IDS,
        max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
    ):
        self.max_tracked_keys = max_tracked_keys
        self.max_groups_per_tenant = max_groups_per_tenant
        self.max_events_per_group = max_events_per_group
        self.max_candidates_per_stage = max_candidates_per_stage
        self.max_seen_event_ids = max_seen_event_ids
        self.max_evidence_bytes = max_evidence_bytes

        self._sequence_windows: OrderedDict[Tuple[str, ...], _TraceSequenceState] = OrderedDict()
        self._threshold_windows: OrderedDict[Tuple[str, ...], _ThresholdCounterState] = OrderedDict()
        self._emitted_keys: Set[Tuple[str, ...]] = set()
        self._emitted_severities: Dict[Tuple[str, ...], str] = {}
        self._tenant_threshold_groups: Dict[str, Set[Tuple[str, ...]]] = defaultdict(set)
        self._tenant_sequence_groups: Dict[str, Set[Tuple[str, ...]]] = defaultdict(set)
        self._lock = threading.RLock()

    def reset(self) -> None:
        with self._lock:
            self._sequence_windows.clear()
            self._threshold_windows.clear()
            self._emitted_keys.clear()
            self._emitted_severities.clear()
            self._tenant_threshold_groups.clear()
            self._tenant_sequence_groups.clear()

    def get_health(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "type": "in_memory",
                "status": "healthy",
                "active_threshold_keys": len(self._threshold_windows),
                "active_sequence_keys": len(self._sequence_windows),
                "resource_limits": {
                    "max_groups_per_tenant": self.max_groups_per_tenant,
                    "max_events_per_group": self.max_events_per_group,
                    "max_candidates_per_stage": self.max_candidates_per_stage,
                    "max_seen_event_ids": self.max_seen_event_ids,
                },
            }

    def _evict_stale(self, reference_ts: datetime.datetime, window_seconds: float, rule_type: str, tenant_id: str):
        cutoff = reference_ts - datetime.timedelta(seconds=window_seconds)
        if rule_type == "sequence":
            keys_to_evict = [
                k for k, state in self._sequence_windows.items()
                if (len(k) > 0 and k[0] == tenant_id) and state.last_seen < cutoff
            ]
            for k in keys_to_evict:
                del self._sequence_windows[k]
                self._tenant_sequence_groups[tenant_id].discard(k)
        else:
            keys_to_evict = [
                k for k, state in self._threshold_windows.items()
                if (len(k) > 0 and k[0] == tenant_id) and state.last_seen < cutoff
            ]
            for k in keys_to_evict:
                del self._threshold_windows[k]
                self._tenant_threshold_groups[tenant_id].discard(k)

    def evaluate_threshold(
        self,
        rule_id: str,
        version: str,
        title: str,
        description: str,
        spec: GenericDeclarativeRuleDefinition,
        event: CanonicalEvent,
        group_key: Tuple[str, ...],
        effective_watermark: datetime.datetime,
    ) -> Optional[Finding]:
        with self._lock:
            tenant_id = event.tenant_id or "default"
            self._evict_stale(effective_watermark, spec.window_seconds, "threshold", tenant_id)

            state = self._threshold_windows.get(group_key)
            if state is None:
                # Enforce tenant group cardinality bound
                if len(self._tenant_threshold_groups[tenant_id]) >= self.max_groups_per_tenant:
                    logger.warning(
                        "Tenant '%s' exceeded max_groups_per_tenant (%d); dropping new threshold group",
                        tenant_id,
                        self.max_groups_per_tenant,
                    )
                    return None

                if len(self._threshold_windows) >= self.max_tracked_keys:
                    evicted_key, _ = self._threshold_windows.popitem(last=False)
                    if len(evicted_key) > 0:
                        self._tenant_threshold_groups[evicted_key[0]].discard(evicted_key)

                state = _ThresholdCounterState(event.timestamp)
                self._threshold_windows[group_key] = state
                self._tenant_threshold_groups[tenant_id].add(group_key)
            else:
                self._threshold_windows.move_to_end(group_key)

            if event.event_id in state.seen_event_ids:
                return None

            # Bounded seen event ids
            if len(state.seen_event_ids) < self.max_seen_event_ids:
                state.seen_event_ids.add(event.event_id)
            state.update_time(event.timestamp)

            # Enforce max events per group
            if state.count >= self.max_events_per_group:
                logger.warning(
                    "Threshold group for rule '%s' exceeded max_events_per_group (%d)",
                    rule_id,
                    self.max_events_per_group,
                )
                return None

            state.count += 1

            spec_thresh = spec.threshold
            metric_val = float(state.count)
            if spec_thresh and spec_thresh.metric == "attribute_sum" and spec_thresh.metric_field:
                from backend.detection.generic_evaluator import _get_nested_field
                raw_field = _get_nested_field(event, spec_thresh.metric_field)
                try:
                    state.aggregated_value += float(raw_field)
                except (ValueError, TypeError):
                    pass
                metric_val = state.aggregated_value
            elif spec_thresh and spec_thresh.metric == "attribute_max" and spec_thresh.metric_field:
                from backend.detection.generic_evaluator import _get_nested_field
                raw_field = _get_nested_field(event, spec_thresh.metric_field)
                try:
                    state.aggregated_value = max(state.aggregated_value, float(raw_field))
                except (ValueError, TypeError):
                    pass
                metric_val = state.aggregated_value

            target = float(spec_thresh.value) if spec_thresh else 1.0
            operator = spec_thresh.operator if spec_thresh else "gte"
            triggered = False
            if operator == "gte" and metric_val >= target:
                triggered = True
            elif operator == "gt" and metric_val > target:
                triggered = True
            elif operator == "equals" and metric_val == target:
                triggered = True

            if triggered:
                base_severity = getattr(spec, "severity", "medium")
                current_severity = "high" if metric_val > 10 else base_severity
                last_emitted = self._emitted_severities.get(group_key)

                if state.finding_emitted:
                    if last_emitted == "high" or last_emitted == current_severity:
                        return None

                self._emitted_severities[group_key] = current_severity
                self._emitted_keys.add(group_key)
                state.finding_emitted = True

                actor = event.source_resource or (event.attributes.get("client_ip") if event.attributes else None) or "unknown_actor"
                evidence = {
                    "group_key": list(group_key),
                    "actor": actor,
                    "attempt_count": state.count,
                    "metric_value": metric_val,
                    "target_resource": event.target_resource,
                    "trace_id": event.trace_id,
                    "supporting_event_ids": list(state.seen_event_ids)[:50],
                    "time_span_seconds": (state.last_seen - state.first_seen).total_seconds(),
                    "rule_id": rule_id,
                    "rule_version": str(version),
                }

                return Finding(
                    tenant_id=tenant_id,
                    detector_id=rule_id,
                    detector_version=str(version),
                    title=f"{title} triggered for {actor}",
                    severity=current_severity,
                    confidence="high",
                    description=f"{description} (Observed metric: {metric_val} vs threshold: {target})",
                    event_id=event.event_id,
                    evidence=evidence,
                )

            return None

    def evaluate_sequence(
        self,
        rule_id: str,
        version: str,
        title: str,
        description: str,
        spec: GenericDeclarativeRuleDefinition,
        event: CanonicalEvent,
        group_key: Tuple[str, ...],
        matched_stage_id: str,
        effective_watermark: datetime.datetime,
    ) -> Optional[Finding]:
        with self._lock:
            tenant_id = event.tenant_id or "default"
            if group_key in self._emitted_keys:
                return None

            self._evict_stale(effective_watermark, spec.window_seconds, "sequence", tenant_id)

            state = self._sequence_windows.get(group_key)
            if state is None:
                # Enforce tenant trace cardinality bound
                if len(self._tenant_sequence_groups[tenant_id]) >= self.max_groups_per_tenant:
                    logger.warning(
                        "Tenant '%s' exceeded max_groups_per_tenant (%d) for sequences; dropping new trace",
                        tenant_id,
                        self.max_groups_per_tenant,
                    )
                    return None

                if len(self._sequence_windows) >= self.max_tracked_keys:
                    evicted_key, _ = self._sequence_windows.popitem(last=False)
                    if len(evicted_key) > 0:
                        self._tenant_sequence_groups[evicted_key[0]].discard(evicted_key)

                state = _TraceSequenceState(event.timestamp)
                self._sequence_windows[group_key] = state
                self._tenant_sequence_groups[tenant_id].add(group_key)
            else:
                self._sequence_windows.move_to_end(group_key)

            if event.event_id in state.seen_event_ids:
                return None

            # Bounded seen set
            if len(state.seen_event_ids) < self.max_seen_event_ids:
                state.seen_event_ids.add(event.event_id)
            state.update_time(event.timestamp)

            # Preserve multiple candidate events per stage up to max_candidates_per_stage
            if matched_stage_id not in state.stage_matches:
                state.stage_matches[matched_stage_id] = []
            if len(state.stage_matches[matched_stage_id]) < self.max_candidates_per_stage:
                state.stage_matches[matched_stage_id].append(event)

            time_window = datetime.timedelta(seconds=spec.window_seconds)
            if (state.last_seen - state.first_seen) > time_window:
                return None

            required_stage_ids = [s.stage_id for s in (spec.sequence_stages or [])]
            for stage_id in required_stage_ids:
                if stage_id not in state.stage_matches or not state.stage_matches[stage_id]:
                    return None

            # Distinct services requirement: union across candidate events for each required stage
            if spec.require_distinct_services:
                services_seen: Set[str] = set()
                for stage_id in required_stage_ids:
                    events = state.stage_matches[stage_id]
                    stage_services = {e.service_id for e in events if e.service_id}
                    if not stage_services:
                        return None
                    services_seen.update(stage_services)
                if len(services_seen) < len(required_stage_ids):
                    return None

            self._emitted_keys.add(group_key)
            state.finding_emitted = True

            stages_evidence: Dict[str, Any] = {}
            all_participating_events: List[str] = []
            for s_id in required_stage_ids:
                m_events = state.stage_matches[s_id]
                lead_ev = m_events[-1]
                c_ids = [e.event_id for e in m_events]
                stages_evidence[s_id] = {
                    "event_id": lead_ev.event_id,
                    "service_id": lead_ev.service_id,
                    "event_type": lead_ev.event_type,
                    "timestamp": lead_ev.timestamp.isoformat(),
                    "target_resource": lead_ev.target_resource,
                    "attributes": lead_ev.attributes,
                    "matched_count": len(m_events),
                    "candidate_event_ids": c_ids,
                }
                all_participating_events.extend(c_ids)

            actor = event.source_resource or (event.attributes.get("client_ip") if event.attributes else None) or "unknown_actor"
            evidence = {
                "group_key": list(group_key),
                "trace_id": event.trace_id,
                "actor": actor,
                "stages": stages_evidence,
                "completed_stages_count": len(required_stage_ids),
                "supporting_event_ids": all_participating_events[:50],
                "duration_seconds": (state.last_seen - state.first_seen).total_seconds(),
                "rule_id": rule_id,
                "rule_version": str(version),
            }

            return Finding(
                tenant_id=tenant_id,
                detector_id=rule_id,
                detector_version=str(version),
                title=f"{title} detected on trace {event.trace_id}",
                severity=getattr(spec, "severity", "high"),
                confidence="high",
                description=f"{description} (Full sequence satisfied across {len(required_stage_ids)} stages)",
                event_id=event.event_id,
                evidence=evidence,
            )


# -----------------------------------------------------------------------------
# Redis Distributed Correlation State Store (Atomic Lua Scripts)
# -----------------------------------------------------------------------------

# Atomic Threshold Evaluation Script with Cardinality & Resource Bounds
_THRESHOLD_LUA = """
local key_state = KEYS[1]
local key_seen = KEYS[2]
local key_tenant_groups = KEYS[3]

local event_id = ARGV[1]
local event_ts = ARGV[2]
local event_epoch = tonumber(ARGV[3])
local window_secs = tonumber(ARGV[4])
local threshold_target = tonumber(ARGV[5])
local base_severity = ARGV[6]
local group_id = ARGV[7]
local max_groups_per_tenant = tonumber(ARGV[8])
local max_events_per_group = tonumber(ARGV[9])
local max_seen_event_ids = tonumber(ARGV[10])

local ttl = window_secs + 120

-- 1. Deduplicate event IDs
if redis.call('SISMEMBER', key_seen, event_id) == 1 then
    return cjson.encode({status = 'duplicate'})
end

-- 2. Tenant Cardinality Guard (max active groups per tenant)
redis.call('ZREMRANGEBYSCORE', key_tenant_groups, '-inf', event_epoch)
local is_existing_group = redis.call('ZSCORE', key_tenant_groups, group_id)
if not is_existing_group then
    local active_groups = redis.call('ZCARD', key_tenant_groups)
    if active_groups >= max_groups_per_tenant then
        return cjson.encode({status = 'limit_exceeded', limit = 'max_groups_per_tenant', count = active_groups})
    end
    redis.call('ZADD', key_tenant_groups, event_epoch + ttl, group_id)
    redis.call('EXPIRE', key_tenant_groups, ttl + 3600)
else
    redis.call('ZADD', key_tenant_groups, event_epoch + ttl, group_id)
end

-- 3. Bounded seen set
local seen_count = redis.call('SCARD', key_seen)
if seen_count < max_seen_event_ids then
    redis.call('SADD', key_seen, event_id)
end

-- 4. Increment and bound attempt count
local count = redis.call('HINCRBY', key_state, 'count', 1)
if count > max_events_per_group then
    redis.call('EXPIRE', key_state, ttl)
    redis.call('EXPIRE', key_seen, ttl)
    return cjson.encode({status = 'limit_exceeded', limit = 'max_events_per_group', count = count})
end

-- 5. Update timestamps and TTL
if count == 1 then
    redis.call('HSET', key_state, 'first_seen', event_ts, 'first_epoch', event_epoch, 'finding_emitted', '0', 'last_severity', '')
end
redis.call('HSET', key_state, 'last_seen', event_ts, 'last_epoch', event_epoch)

redis.call('EXPIRE', key_state, ttl)
redis.call('EXPIRE', key_seen, ttl)

-- 6. Check threshold
if count >= threshold_target then
    local curr_sev = (count > 10) and 'high' or base_severity
    local last_sev = redis.call('HGET', key_state, 'last_severity') or ''
    local emitted = redis.call('HGET', key_state, 'finding_emitted') or '0'

    if emitted == '0' or (curr_sev == 'high' and last_sev ~= 'high') then
        redis.call('HSET', key_state, 'finding_emitted', '1', 'last_severity', curr_sev)
        local first_seen = redis.call('HGET', key_state, 'first_seen') or event_ts
        local first_epoch = tonumber(redis.call('HGET', key_state, 'first_epoch') or event_epoch)
        local supporting_members = redis.call('SMEMBERS', key_seen)
        return cjson.encode({
            status = 'triggered',
            count = count,
            severity = curr_sev,
            first_seen = first_seen,
            span_seconds = event_epoch - first_epoch,
            supporting_event_ids = supporting_members
        })
    else
        return cjson.encode({status = 'suppressed', count = count, severity = curr_sev})
    end
end

return cjson.encode({status = 'below', count = count})
"""

# Atomic Sequence Transition Script with Multi-Candidate Stage Preservation
_SEQUENCE_LUA = """
local key_state = KEYS[1]
local key_seen = KEYS[2]
local key_stages = KEYS[3]
local key_tenant_traces = KEYS[4]

local event_id = ARGV[1]
local stage_id = ARGV[2]
local service_id = ARGV[3]
local event_data = ARGV[4]
local event_epoch = tonumber(ARGV[5])
local window_secs = tonumber(ARGV[6])
local required_stages_csv = ARGV[7]
local require_distinct = ARGV[8]
local rule_severity = ARGV[9]
local trace_id = ARGV[10]
local max_groups_per_tenant = tonumber(ARGV[11])
local max_candidates_per_stage = tonumber(ARGV[12])
local max_seen_event_ids = tonumber(ARGV[13])

local ttl = window_secs + 120

-- 1. Deduplicate event IDs
if redis.call('SISMEMBER', key_seen, event_id) == 1 then
    return cjson.encode({status = 'duplicate'})
end

-- 2. Check if trace already emitted finding
if redis.call('HGET', key_state, 'emitted') == '1' then
    return cjson.encode({status = 'already_emitted'})
end

-- 3. Tenant Cardinality Guard (max active traces per tenant)
redis.call('ZREMRANGEBYSCORE', key_tenant_traces, '-inf', event_epoch)
local is_existing_trace = redis.call('ZSCORE', key_tenant_traces, trace_id)
if not is_existing_trace then
    local active_traces = redis.call('ZCARD', key_tenant_traces)
    if active_traces >= max_groups_per_tenant then
        return cjson.encode({status = 'limit_exceeded', limit = 'max_groups_per_tenant', count = active_traces})
    end
    redis.call('ZADD', key_tenant_traces, event_epoch + ttl, trace_id)
    redis.call('EXPIRE', key_tenant_traces, ttl + 3600)
else
    redis.call('ZADD', key_tenant_traces, event_epoch + ttl, trace_id)
end

-- 4. Bounded seen set
local seen_count = redis.call('SCARD', key_seen)
if seen_count < max_seen_event_ids then
    redis.call('SADD', key_seen, event_id)
end

-- 5. Multi-candidate storage per stage in key_stages
local existing_raw = redis.call('HGET', key_stages, stage_id)
local stage_events = {}
if existing_raw and existing_raw ~= '' then
    stage_events = cjson.decode(existing_raw)
end

if #stage_events < max_candidates_per_stage then
    table.insert(stage_events, cjson.decode(event_data))
    redis.call('HSET', key_stages, stage_id, cjson.encode(stage_events))
end

-- 6. Update epochs atomically
local first_ep = redis.call('HGET', key_state, 'first_epoch')
if not first_ep or event_epoch < tonumber(first_ep) then
    redis.call('HSET', key_state, 'first_epoch', event_epoch)
    first_ep = event_epoch
end

local last_ep = redis.call('HGET', key_state, 'last_epoch')
if not last_ep or event_epoch > tonumber(last_ep) then
    redis.call('HSET', key_state, 'last_epoch', event_epoch)
    last_ep = event_epoch
end

-- 7. Refresh TTLs
redis.call('EXPIRE', key_state, ttl)
redis.call('EXPIRE', key_seen, ttl)
redis.call('EXPIRE', key_stages, ttl)

-- 8. Check sliding window duration
local span = tonumber(last_ep) - tonumber(first_ep)
if span > window_secs then
    return cjson.encode({status = 'window_expired', span = span, max_window = window_secs})
end

-- 9. Check all required stages exist
local required_stages = {}
for s in string.gmatch(required_stages_csv, "([^,]+)") do
    table.insert(required_stages, s)
    if redis.call('HEXISTS', key_stages, s) == 0 then
        return cjson.encode({status = 'incomplete_stages'})
    end
end

-- 10. Check distinct services requirement across candidates
if require_distinct == '1' then
    local seen_services = {}
    local distinct_count = 0
    for _, s in ipairs(required_stages) do
        local raw_stg = redis.call('HGET', key_stages, s)
        local stg_list = cjson.decode(raw_stg)
        for _, ev in ipairs(stg_list) do
            local svc = ev.service_id
            if svc and svc ~= '' and not seen_services[svc] then
                seen_services[svc] = true
                distinct_count = distinct_count + 1
            end
        end
    end
    if distinct_count < #required_stages then
        return cjson.encode({status = 'duplicate_services', distinct_count = distinct_count, required = #required_stages})
    end
end

-- 11. Sequence fully satisfied! Mark emitted to prevent alert storms
redis.call('HSET', key_state, 'emitted', '1')

local stages_payload = {}
local supporting_event_ids = {}

for _, s in ipairs(required_stages) do
    local raw_stg = redis.call('HGET', key_stages, s)
    local stg_list = cjson.decode(raw_stg)
    local lead_ev = stg_list[#stg_list]
    local c_ids = {}
    for _, ev in ipairs(stg_list) do
        table.insert(c_ids, ev.event_id)
        table.insert(supporting_event_ids, ev.event_id)
    end
    stages_payload[s] = {
        event_id = lead_ev.event_id,
        service_id = lead_ev.service_id,
        event_type = lead_ev.event_type,
        timestamp = lead_ev.timestamp,
        target_resource = lead_ev.target_resource,
        attributes = lead_ev.attributes,
        matched_count = #stg_list,
        candidate_event_ids = c_ids
    }
end

return cjson.encode({
    status = 'triggered',
    severity = rule_severity,
    stages = stages_payload,
    supporting_event_ids = supporting_event_ids,
    duration = span
})
"""


class RedisCorrelationStateStore(BaseCorrelationStore):
    """
    Distributed, atomic correlation state store backed by Redis and server-side Lua scripts.
    Supports horizontal scaling across multiple independent worker processes with resource bounds.
    """

    def __init__(
        self,
        redis_client_or_url: Union[str, Any],
        socket_timeout: float = 0.5,
        max_connections: int = 50,
        max_groups_per_tenant: int = DEFAULT_MAX_GROUPS_PER_TENANT,
        max_events_per_group: int = DEFAULT_MAX_EVENTS_PER_THRESHOLD_GROUP,
        max_candidates_per_stage: int = DEFAULT_MAX_CANDIDATES_PER_STAGE,
        max_seen_event_ids: int = DEFAULT_MAX_SEEN_EVENT_IDS,
        max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
    ):
        self.max_groups_per_tenant = max_groups_per_tenant
        self.max_events_per_group = max_events_per_group
        self.max_candidates_per_stage = max_candidates_per_stage
        self.max_seen_event_ids = max_seen_event_ids
        self.max_evidence_bytes = max_evidence_bytes

        if isinstance(redis_client_or_url, str):
            import redis
            self.pool = redis.ConnectionPool.from_url(
                redis_client_or_url,
                max_connections=max_connections,
                socket_timeout=socket_timeout,
                socket_connect_timeout=socket_timeout,
                decode_responses=True,
            )
            self.client = redis.Redis(connection_pool=self.pool)
        else:
            self.client = redis_client_or_url

        self._threshold_sha: Optional[str] = None
        self._sequence_sha: Optional[str] = None
        self._load_scripts()

    def _load_scripts(self):
        try:
            self._threshold_sha = self.client.script_load(_THRESHOLD_LUA)
            self._sequence_sha = self.client.script_load(_SEQUENCE_LUA)
        except Exception as e:
            logger.warning("Could not pre-load Lua scripts into Redis (will fallback to eval): %s", e)

    def _exec_script(self, script_text: str, script_sha: Optional[str], numkeys: int, *keys_and_args) -> str:
        try:
            if script_sha:
                return self.client.evalsha(script_sha, numkeys, *keys_and_args)
            return self.client.eval(script_text, numkeys, *keys_and_args)
        except Exception as err:
            # If NOSCRIPT, reload and retry
            if "NOSCRIPT" in str(err):
                return self.client.eval(script_text, numkeys, *keys_and_args)
            raise

    def get_health(self) -> Dict[str, Any]:
        try:
            ping_ok = self.client.ping()
            return {
                "type": "redis",
                "status": "healthy" if ping_ok else "unhealthy",
                "connected": bool(ping_ok),
                "resource_limits": {
                    "max_groups_per_tenant": self.max_groups_per_tenant,
                    "max_events_per_group": self.max_events_per_group,
                    "max_candidates_per_stage": self.max_candidates_per_stage,
                    "max_seen_event_ids": self.max_seen_event_ids,
                },
            }
        except Exception as e:
            return {
                "type": "redis",
                "status": "degraded",
                "connected": False,
                "error": str(e),
            }

    def reset(self) -> None:
        """Purges all keys matching ternline:* namespace."""
        try:
            cursor = 0
            while True:
                cursor, keys = self.client.scan(cursor=cursor, match="ternline:*", count=500)
                if keys:
                    self.client.delete(*keys)
                if cursor == 0:
                    break
        except Exception as err:
            logger.error("Failed purging Redis correlation keys: %s", err)

    def _make_group_hash(self, group_key: Tuple[str, ...]) -> str:
        raw = ":".join(str(p) for p in group_key)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def evaluate_threshold(
        self,
        rule_id: str,
        version: str,
        title: str,
        description: str,
        spec: GenericDeclarativeRuleDefinition,
        event: CanonicalEvent,
        group_key: Tuple[str, ...],
        effective_watermark: datetime.datetime,
    ) -> Optional[Finding]:
        tenant_id = event.tenant_id or "default"
        ghash = self._make_group_hash(group_key)

        key_state = f"ternline:{tenant_id}:rule:{rule_id}:v{version}:thresh:{ghash}"
        key_seen = f"ternline:{tenant_id}:rule:{rule_id}:v{version}:thresh:{ghash}:seen"
        key_tenant_groups = f"ternline:{tenant_id}:active_threshold_groups"

        ev_epoch = event.timestamp.timestamp()
        target_count = int(spec.threshold.value) if spec.threshold else 1
        base_severity = getattr(spec, "severity", "medium")

        try:
            raw_res = self._exec_script(
                _THRESHOLD_LUA,
                self._threshold_sha,
                3,
                key_state,
                key_seen,
                key_tenant_groups,
                event.event_id,
                event.timestamp.isoformat(),
                ev_epoch,
                spec.window_seconds,
                target_count,
                base_severity,
                ghash,
                self.max_groups_per_tenant,
                self.max_events_per_group,
                self.max_seen_event_ids,
            )
            res = json.loads(raw_res)
        except Exception as e:
            logger.error("Redis threshold evaluation failed for rule '%s': %s", rule_id, e)
            raise RedisStateError(f"Redis threshold evaluation failure: {e}") from e

        status = res.get("status")
        if status == "limit_exceeded":
            logger.warning(
                "Threshold rule '%s' exceeded resource limit '%s' (current: %s)",
                rule_id,
                res.get("limit"),
                res.get("count"),
            )
            return None

        if status == "triggered":
            actor = event.source_resource or (event.attributes.get("client_ip") if event.attributes else None) or "unknown_actor"
            count = res["count"]
            curr_sev = res["severity"]

            evidence = {
                "group_key": list(group_key),
                "actor": actor,
                "attempt_count": count,
                "metric_value": count,
                "target_resource": event.target_resource,
                "trace_id": event.trace_id,
                "supporting_event_ids": res.get("supporting_event_ids", [])[:50],
                "time_span_seconds": res.get("span_seconds", 0.0),
                "rule_id": rule_id,
                "rule_version": str(version),
                "distributed_state": True,
            }

            return Finding(
                tenant_id=tenant_id,
                detector_id=rule_id,
                detector_version=str(version),
                title=f"{title} triggered for {actor}",
                severity=curr_sev,
                confidence="high",
                description=f"{description} (Observed metric: {count} vs threshold: {target_count})",
                event_id=event.event_id,
                evidence=evidence,
            )

        return None

    def evaluate_sequence(
        self,
        rule_id: str,
        version: str,
        title: str,
        description: str,
        spec: GenericDeclarativeRuleDefinition,
        event: CanonicalEvent,
        group_key: Tuple[str, ...],
        matched_stage_id: str,
        effective_watermark: datetime.datetime,
    ) -> Optional[Finding]:
        tenant_id = event.tenant_id or "default"
        trace_id = event.trace_id or "unknown_trace"

        key_state = f"ternline:{tenant_id}:rule:{rule_id}:v{version}:seq:{trace_id}"
        key_seen = f"ternline:{tenant_id}:rule:{rule_id}:v{version}:seq:{trace_id}:seen"
        key_stages = f"ternline:{tenant_id}:rule:{rule_id}:v{version}:seq:{trace_id}:stages"
        key_tenant_traces = f"ternline:{tenant_id}:active_sequence_traces"

        ev_epoch = event.timestamp.timestamp()
        required_stages = [s.stage_id for s in (spec.sequence_stages or [])]
        required_stages_csv = ",".join(required_stages)
        require_distinct = "1" if spec.require_distinct_services else "0"
        rule_severity = getattr(spec, "severity", "high")

        # Bound event summary payload size
        sanitized_attrs = {}
        if event.attributes:
            for k, v in list(event.attributes.items())[:20]:
                str_v = str(v)
                sanitized_attrs[k] = str_v[:256] if len(str_v) > 256 else v

        event_summary = {
            "event_id": event.event_id,
            "service_id": event.service_id,
            "event_type": event.event_type,
            "timestamp": event.timestamp.isoformat(),
            "target_resource": event.target_resource,
            "attributes": sanitized_attrs,
        }

        try:
            raw_res = self._exec_script(
                _SEQUENCE_LUA,
                self._sequence_sha,
                4,
                key_state,
                key_seen,
                key_stages,
                key_tenant_traces,
                event.event_id,
                matched_stage_id,
                event.service_id or "unknown_service",
                json.dumps(event_summary),
                ev_epoch,
                spec.window_seconds,
                required_stages_csv,
                require_distinct,
                rule_severity,
                trace_id,
                self.max_groups_per_tenant,
                self.max_candidates_per_stage,
                self.max_seen_event_ids,
            )
            res = json.loads(raw_res)
        except Exception as e:
            logger.error("Redis sequence evaluation failed for rule '%s': %s", rule_id, e)
            raise RedisStateError(f"Redis sequence evaluation failure: {e}") from e

        status = res.get("status")
        if status == "limit_exceeded":
            logger.warning(
                "Sequence rule '%s' exceeded resource limit '%s' on trace '%s' (current: %s)",
                rule_id,
                res.get("limit"),
                trace_id,
                res.get("count"),
            )
            return None

        if status == "triggered":
            actor = event.source_resource or (event.attributes.get("client_ip") if event.attributes else None) or "unknown_actor"
            evidence = {
                "group_key": list(group_key),
                "trace_id": event.trace_id,
                "actor": actor,
                "stages": res.get("stages", {}),
                "completed_stages_count": len(required_stages),
                "supporting_event_ids": res.get("supporting_event_ids", [])[:50],
                "duration_seconds": res.get("duration", 0.0),
                "rule_id": rule_id,
                "rule_version": str(version),
                "distributed_state": True,
            }

            return Finding(
                tenant_id=tenant_id,
                detector_id=rule_id,
                detector_version=str(version),
                title=f"{title} detected on trace {event.trace_id}",
                severity=res.get("severity", rule_severity),
                confidence="high",
                description=f"{description} (Full sequence satisfied across {len(required_stages)} stages)",
                event_id=event.event_id,
                evidence=evidence,
            )

        return None
