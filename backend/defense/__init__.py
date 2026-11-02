"""
Ternline Active Defense Module.
Contains response planning, policy evaluation, action authorization, approval gating, and ingestion containment filters.
"""

from backend.defense.planner import ResponsePlanner
from backend.defense.policy import PolicyEvaluator
from backend.defense.approval import ApprovalManager
from backend.defense.filter import IngestContainmentFilter, ingest_containment_filter
from backend.defense.adapters import (
    BaseDefenseAdapter,
    InternalApiKeyAdapter,
    RedisIngestBlockAdapter,
    RedisRateLimitAdapter,
    WebhookContainmentAdapter,
)
from backend.defense.executor import ResponseExecutor
from backend.defense.verification import VerificationManager
from backend.defense.rollback import RollbackManager

__all__ = [
    "ResponsePlanner",
    "PolicyEvaluator",
    "ApprovalManager",
    "IngestContainmentFilter",
    "ingest_containment_filter",
    "BaseDefenseAdapter",
    "InternalApiKeyAdapter",
    "RedisIngestBlockAdapter",
    "RedisRateLimitAdapter",
    "WebhookContainmentAdapter",
    "ResponseExecutor",
    "VerificationManager",
    "RollbackManager",
]
