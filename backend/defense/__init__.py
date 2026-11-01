"""
Ternline Active Defense Module.
Contains response planning, policy evaluation, action authorization, approval gating, and ingestion containment filters.
"""

from backend.defense.planner import ResponsePlanner
from backend.defense.policy import PolicyEvaluator
from backend.defense.approval import ApprovalManager
from backend.defense.filter import IngestContainmentFilter, ingest_containment_filter

__all__ = [
    "ResponsePlanner",
    "PolicyEvaluator",
    "ApprovalManager",
    "IngestContainmentFilter",
    "ingest_containment_filter",
]
