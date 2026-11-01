"""
Response Planner for Ternline Phase 1: Active Defense.

Responsibilities:
1. Translates SecurityFindings and Deep Track investigation recommendations into normalized CandidateResponseActions.
2. Differentiates perimeter ingestion containment from customer application containment.
3. Delineates Ternline-managed credentials from external customer OAuth/IdP credentials.
4. Computes deterministic, collision-resistant SHA-256 fingerprints.
5. Detects duplicate actions and coalesces them to prevent duplicate executions or conflicting states.
6. Enforces tenant isolation and rejects invalid or protected targets.
7. Durably persists proposed actions and audit records to PostgreSQL before any downstream dispatch.
"""

import datetime
import logging
import re
import threading
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union
from sqlalchemy.orm import Session

from backend.models import (
    DefenseActionModel,
    DefenseAuditLogModel,
    SecurityFinding,
    TenantDefensePolicyModel,
)
from backend.schemas.defense import (
    ActionScope,
    ActionStatus,
    ActionType,
    CandidateResponseAction,
    CredentialAuthority,
    PlannedResponseAction,
    ProtectionMode,
    TargetEntityType,
    compute_action_fingerprint,
)
from backend.schemas.investigation import InvestigationFinding

logger = logging.getLogger("cyber_engine.defense.planner")

# Protected targets that can never be contained/blocked to prevent self-inflicted outages
PROTECTED_ENTITIES = {
    "127.0.0.1",
    "::1",
    "localhost",
    "0.0.0.0",
    "internal-db",
    "postgres",
    "redis",
}

# Regex patterns for parsing unstructured recommendation strings
REVOKE_KEY_PATTERN = re.compile(r"revoke\s+(?:api\s+)?key\s+([A-Za-z0-9_\-\.]+)", re.IGNORECASE)
BLOCK_IP_PATTERN = re.compile(r"block\s+(?:ip\s+)?([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:/\d{1,2})?)", re.IGNORECASE)
RATE_LIMIT_PATTERN = re.compile(r"(?:rate\s+limit|throttle)\s+(?:client\s+|ip\s+|app\s+)?([A-Za-z0-9_\-\.]+)", re.IGNORECASE)
CONTAIN_USER_PATTERN = re.compile(r"(?:contain|suspend)\s+(?:user|account|session)\s+([A-Za-z0-9_\-\.]+)", re.IGNORECASE)


class ResponsePlanner:
    """
    Synthesizes, validates, deduplicates, and persists Active Defense response action plans.
    """

    def __init__(self, db: Session):
        self.db = db
        self._lock = threading.RLock()

    def plan_from_finding(
        self,
        finding: SecurityFinding,
        context: Optional[Union[InvestigationFinding, Dict[str, Any]]] = None,
    ) -> List[PlannedResponseAction]:
        """
        Main entrypoint: Transforms a SecurityFinding and optional investigation context
        into durably stored, deduplicated PlannedResponseActions.
        """
        if not finding or not finding.tenant_id:
            raise ValueError("A valid SecurityFinding with a tenant_id is required")

        tenant_id = finding.tenant_id

        # 1. Resolve tenant's configured protection mode (mandatory default: OBSERVE)
        policy_mode = self._get_tenant_protection_mode(tenant_id)

        # 2. Extract and normalize candidates from investigation context or finding heuristics
        candidates: List[CandidateResponseAction] = []
        if context:
            candidates.extend(self._extract_from_context(finding, context))

        if not candidates:
            # Fallback to finding baseline heuristics if no investigation context provided
            candidates.extend(self._extract_from_finding_heuristics(finding))

        # 3. Filter invalid, protected, or unsupported candidates
        valid_candidates: List[CandidateResponseAction] = []
        for cand in candidates:
            if self._is_valid_candidate(cand):
                valid_candidates.append(cand)
            else:
                logger.warning(
                    "Rejected invalid or protected response candidate: type=%s target=%s tenant=%s",
                    cand.action_type, cand.target_entity_id, tenant_id
                )

        # 4. Atomically persist or coalesce each valid candidate under tenant lock
        planned_actions: List[PlannedResponseAction] = []
        with self._lock:
            for cand in valid_candidates:
                action = self._persist_or_coalesce_action(finding, cand, policy_mode)
                if action:
                    planned_actions.append(action)

        return planned_actions

    def _get_tenant_protection_mode(self, tenant_id: str) -> ProtectionMode:
        """
        Retrieves tenant default protection mode. Strictly defaults to OBSERVE if unset.
        """
        policy = (
            self.db.query(TenantDefensePolicyModel)
            .filter(TenantDefensePolicyModel.tenant_id == tenant_id)
            .first()
        )
        if policy and policy.default_mode:
            try:
                return ProtectionMode(policy.default_mode.lower())
            except ValueError:
                pass
        return ProtectionMode.OBSERVE

    def _is_valid_candidate(self, cand: CandidateResponseAction) -> bool:
        """
        Validates target entity safety and format.
        """
        target = (cand.target_entity_id or "").strip().lower()
        if not target:
            return False
        if target in PROTECTED_ENTITIES:
            return False
        # Prevent shell / script injection in entity parameters or target
        if any(c in target for c in (";", "|", "&", "$", "`", "\n", "\r")):
            return False
        return True

    def _extract_from_context(
        self,
        finding: SecurityFinding,
        context: Union[InvestigationFinding, Dict[str, Any]],
    ) -> List[CandidateResponseAction]:
        """
        Normalizes recommendations from Deep Track investigation reports.
        """
        candidates: List[CandidateResponseAction] = []
        raw_recs: List[Any] = []

        if isinstance(context, InvestigationFinding):
            raw_recs = context.recommended_mitigations or []
        elif isinstance(context, dict):
            raw_recs = context.get("recommended_mitigations") or []

        for rec in raw_recs:
            cand = self.normalize_recommendation(rec, finding)
            if cand:
                candidates.append(cand)

        return candidates

    def normalize_recommendation(
        self,
        rec: Union[str, Dict[str, Any]],
        finding: SecurityFinding,
    ) -> Optional[CandidateResponseAction]:
        """
        Parses structured dictionary or unstructured natural language recommendation
        into a strongly-typed CandidateResponseAction.
        """
        tenant_id = finding.tenant_id
        finding_id = finding.finding_id

        # Case A: Structured Dictionary
        if isinstance(rec, dict):
            try:
                action_type_raw = rec.get("action_type")
                target_id = rec.get("target_entity_id") or rec.get("target")
                if not action_type_raw or not target_id:
                    return None

                action_type = ActionType(action_type_raw)
                entity_type = TargetEntityType(rec.get("target_entity_type", "ip_address"))
                scope = ActionScope(rec.get("scope", ActionScope.TERNLINE_INGEST.value))
                authority = None
                if action_type == ActionType.API_KEY_REVOCATION:
                    authority = CredentialAuthority(
                        rec.get("credential_authority", CredentialAuthority.TERNLINE_MANAGED.value)
                    )

                return CandidateResponseAction(
                    action_type=action_type,
                    scope=scope,
                    credential_authority=authority,
                    target_entity_type=entity_type,
                    target_entity_id=str(target_id).strip(),
                    parameters=rec.get("parameters", {}),
                    ttl_seconds=rec.get("ttl_seconds", 3600 if "temporary" in action_type.value else None),
                    rationale=rec.get("rationale", f"Recommended by Deep Track investigation for finding {finding_id}"),
                    finding_id=finding_id,
                )
            except (ValueError, TypeError) as e:
                logger.debug("Failed parsing structured recommendation: %s (%s)", rec, e)
                return None

        # Case B: Unstructured Text Parsing
        if isinstance(rec, str):
            text = rec.strip()

            # 1. API Key Revocation
            m = REVOKE_KEY_PATTERN.search(text)
            if m:
                key_id = m.group(1).strip()
                # Determine authority: if key starts with standard Ternline prefix or is known
                auth = CredentialAuthority.TERNLINE_MANAGED if (key_id.startswith("ce_") or "key-" in key_id) else CredentialAuthority.EXTERNAL_CUSTOMER
                return CandidateResponseAction(
                    action_type=ActionType.API_KEY_REVOCATION,
                    scope=ActionScope.TERNLINE_INGEST if auth == CredentialAuthority.TERNLINE_MANAGED else ActionScope.CUSTOMER_APPLICATION,
                    credential_authority=auth,
                    target_entity_type=TargetEntityType.API_KEY,
                    target_entity_id=key_id,
                    parameters={"reason": "Compromised API key identified in security investigation"},
                    ttl_seconds=None,  # Permanent by default
                    rationale=text,
                    finding_id=finding_id,
                )

            # 2. Temporary IP Block
            m = BLOCK_IP_PATTERN.search(text)
            if m:
                ip = m.group(1).strip()
                return CandidateResponseAction(
                    action_type=ActionType.TEMPORARY_IP_BLOCK,
                    scope=ActionScope.TERNLINE_INGEST,
                    credential_authority=None,
                    target_entity_type=TargetEntityType.IP_ADDRESS,
                    target_entity_id=ip,
                    parameters={"block_duration_minutes": 30},
                    ttl_seconds=1800,
                    rationale=text,
                    finding_id=finding_id,
                )

            # 3. Temporary Rate Limit
            m = RATE_LIMIT_PATTERN.search(text)
            if m:
                target = m.group(1).strip()
                is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))
                return CandidateResponseAction(
                    action_type=ActionType.TEMPORARY_RATE_LIMIT,
                    scope=ActionScope.TERNLINE_INGEST,
                    credential_authority=None,
                    target_entity_type=TargetEntityType.IP_ADDRESS if is_ip else TargetEntityType.APP_ID,
                    target_entity_id=target,
                    parameters={"max_requests_per_minute": 10},
                    ttl_seconds=3600,
                    rationale=text,
                    finding_id=finding_id,
                )

            # 4. Account / Session Containment
            m = CONTAIN_USER_PATTERN.search(text)
            if m:
                user_id = m.group(1).strip()
                return CandidateResponseAction(
                    action_type=ActionType.ACCOUNT_SESSION_CONTAINMENT,
                    scope=ActionScope.CUSTOMER_APPLICATION,
                    credential_authority=CredentialAuthority.EXTERNAL_CUSTOMER,
                    target_entity_type=TargetEntityType.USER_ID,
                    target_entity_id=user_id,
                    parameters={"session_invalidation": True},
                    ttl_seconds=7200,
                    rationale=text,
                    finding_id=finding_id,
                )

        return None

    def _extract_from_finding_heuristics(
        self, finding: SecurityFinding
    ) -> List[CandidateResponseAction]:
        """
        Derives baseline response candidates directly from SecurityFinding detector metadata.
        """
        candidates: List[CandidateResponseAction] = []
        det = (finding.detector_id or "").lower()
        ev = finding.evidence or {}

        client_ip = ev.get("client_ip") or ev.get("source_ip") or finding.source_resource if hasattr(finding, "source_resource") else None
        if not client_ip and isinstance(ev, dict):
            # Inspect first nested event attribute if present
            for k in ("ip", "client_ip", "remote_addr"):
                if ev.get(k):
                    client_ip = ev[k]
                    break

        # Brute force or password spray -> Temporary IP block
        if "brute_force" in det or "password_spray" in det:
            if client_ip and self._is_valid_candidate_target(client_ip):
                candidates.append(
                    CandidateResponseAction(
                        action_type=ActionType.TEMPORARY_IP_BLOCK,
                        scope=ActionScope.TERNLINE_INGEST,
                        credential_authority=None,
                        target_entity_type=TargetEntityType.IP_ADDRESS,
                        target_entity_id=str(client_ip).strip(),
                        parameters={"block_duration_minutes": 30},
                        ttl_seconds=1800,
                        rationale=f"Automated defense proposal: excessive authentication failures ({finding.title})",
                        finding_id=finding.finding_id,
                    )
                )

        # Exfiltration or credential abuse -> API Key Revocation or Rate Limit
        if "exfiltration" in det or "credential_abuse" in det:
            app_id = ev.get("app_id")
            if app_id:
                candidates.append(
                    CandidateResponseAction(
                        action_type=ActionType.TEMPORARY_RATE_LIMIT,
                        scope=ActionScope.TERNLINE_INGEST,
                        credential_authority=None,
                        target_entity_type=TargetEntityType.APP_ID,
                        target_entity_id=str(app_id).strip(),
                        parameters={"max_requests_per_minute": 5},
                        ttl_seconds=3600,
                        rationale=f"Automated defense proposal: suspicious data volume detected ({finding.title})",
                        finding_id=finding.finding_id,
                    )
                )

        return candidates

    def _is_valid_candidate_target(self, target: Any) -> bool:
        if not target or not isinstance(target, str):
            return False
        s = target.strip().lower()
        return bool(s) and s not in PROTECTED_ENTITIES

    def _persist_or_coalesce_action(
        self,
        finding: SecurityFinding,
        cand: CandidateResponseAction,
        policy_mode: ProtectionMode,
    ) -> PlannedResponseAction:
        """
        Computes deterministic fingerprint, checks for active duplicates,
        coalesces if active, or persists a new action to PostgreSQL.
        """
        fingerprint = compute_action_fingerprint(
            tenant_id=finding.tenant_id,
            action_type=cand.action_type.value,
            target_entity_type=cand.target_entity_type.value,
            target_entity_id=cand.target_entity_id,
            parameters=cand.parameters,
        )

        now = datetime.datetime.now(datetime.timezone.utc)

        # 1. Check for existing active or pending action with identical fingerprint in this tenant
        existing = (
            self.db.query(DefenseActionModel)
            .filter(
                DefenseActionModel.tenant_id == finding.tenant_id,
                DefenseActionModel.deduplication_fingerprint == fingerprint,
                DefenseActionModel.status.in_([
                    ActionStatus.PROPOSED.value,
                    ActionStatus.AWAITING_APPROVAL.value,
                    ActionStatus.APPROVED.value,
                    ActionStatus.EXECUTING.value,
                    ActionStatus.VERIFYING.value,
                    ActionStatus.VERIFIED_ACTIVE.value,
                ]),
            )
            .first()
        )

        if existing:
            logger.info(
                "Coalesced duplicate defense action: tenant=%s fingerprint=%s existing_action_id=%s finding_id=%s",
                finding.tenant_id, fingerprint, existing.action_id, finding.finding_id
            )
            # Log coalescence to immutable audit trail
            audit_log = DefenseAuditLogModel(
                log_id=f"log-{uuid.uuid4().hex[:12]}",
                action_id=existing.action_id,
                tenant_id=finding.tenant_id,
                from_status=existing.status,
                to_status=existing.status,
                transition_trigger="response_planner.coalesce_duplicate",
                actor="system:response_planner",
                details={
                    "coalesced_finding_id": finding.finding_id,
                    "target_entity": cand.target_entity_id,
                    "action_type": cand.action_type.value,
                },
                timestamp=now,
            )
            self.db.add(audit_log)
            self.db.commit()
            return self._model_to_planned(existing)

        # 2. Persist new action
        action_id = f"act-{uuid.uuid4().hex[:12]}"
        expires_at = None
        if cand.ttl_seconds:
            expires_at = now + datetime.timedelta(seconds=cand.ttl_seconds)

        new_action = DefenseActionModel(
            action_id=action_id,
            tenant_id=finding.tenant_id,
            finding_id=finding.finding_id,
            action_type=cand.action_type.value,
            scope=cand.scope.value,
            credential_authority=cand.credential_authority.value if cand.credential_authority else None,
            target_entity_type=cand.target_entity_type.value,
            target_entity_id=cand.target_entity_id,
            status=ActionStatus.PROPOSED.value,
            protection_mode=policy_mode.value,
            deduplication_fingerprint=fingerprint,
            parameters=cand.parameters or {},
            ttl_seconds=cand.ttl_seconds,
            expires_at=expires_at,
            requested_by="system:response_planner",
            approval_rationale=cand.rationale,
            created_at=now,
        )
        self.db.add(new_action)

        # Create initial audit log entry
        audit_log = DefenseAuditLogModel(
            log_id=f"log-{uuid.uuid4().hex[:12]}",
            action_id=action_id,
            tenant_id=finding.tenant_id,
            from_status=None,
            to_status=ActionStatus.PROPOSED.value,
            transition_trigger="response_planner.propose",
            actor="system:response_planner",
            details={
                "finding_id": finding.finding_id,
                "action_type": cand.action_type.value,
                "target_entity": cand.target_entity_id,
                "protection_mode": policy_mode.value,
                "fingerprint": fingerprint,
            },
            timestamp=now,
        )
        self.db.add(audit_log)

        # Durable commit before returning
        self.db.commit()
        self.db.refresh(new_action)

        logger.info(
            "Created planned defense action: action_id=%s tenant=%s type=%s mode=%s target=%s",
            action_id, finding.tenant_id, cand.action_type.value, policy_mode.value, cand.target_entity_id
        )

        return self._model_to_planned(new_action)

    def _model_to_planned(self, model: DefenseActionModel) -> PlannedResponseAction:
        return PlannedResponseAction(
            action_id=model.action_id,
            tenant_id=model.tenant_id,
            finding_id=model.finding_id,
            action_type=ActionType(model.action_type),
            scope=ActionScope(model.scope),
            credential_authority=CredentialAuthority(model.credential_authority) if model.credential_authority else None,
            target_entity_type=TargetEntityType(model.target_entity_type),
            target_entity_id=model.target_entity_id,
            status=ActionStatus(model.status),
            protection_mode=ProtectionMode(model.protection_mode),
            deduplication_fingerprint=model.deduplication_fingerprint,
            parameters=model.parameters or {},
            ttl_seconds=model.ttl_seconds,
            expires_at=model.expires_at,
            requested_by=model.requested_by,
            approved_by=model.approved_by,
            approval_rationale=model.approval_rationale,
            provider_adapter=model.provider_adapter,
            external_reference_id=model.external_reference_id,
            execution_result=model.execution_result,
            verification_result=model.verification_result,
            rollback_result=model.rollback_result,
            created_at=model.created_at,
            executed_at=model.executed_at,
            verified_at=model.verified_at,
            rolled_back_at=model.rolled_back_at,
        )

