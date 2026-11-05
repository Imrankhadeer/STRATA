"""
FastAPI Endpoints for Declarative Rule Management and Replay Validation.

Provides:
- Proposing candidate declarative rules
- Running automated scenario replay validation
- Approval gating (requiring validation pass before approval)
- Activation into the Fast Track registry
- Full tenant boundary isolation
"""

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from pydantic import ValidationError
import logging
import datetime

from backend.db.session import get_db
from backend.core.auth import get_current_auth, AuthContext, Permission, require_permission
from backend.models import DeclarativeRuleModel
from backend.schemas.rules import (
    DeclarativeRule,
    ReplayValidationMetrics,
    ApprovalRecord,
    DisableRuleRequest,
    RollbackRuleRequest,
)
from backend.detection.replay import ReplayValidationEngine
from backend.detection.registry import runtime_rule_registry
from backend.ops.bus import ops_bus

router = APIRouter(prefix="/api/v1/rules", tags=["Rules Registry & Validation"])
logger = logging.getLogger(__name__)


class CreateRuleRequest(BaseModel):
    target_detector: str
    title: str
    description: str
    parameters: dict


class ApprovalRequest(BaseModel):
    decision: str = Field(default="approved", pattern="^(approved|rejected)$")
    rationale: str


@router.post("", response_model=DeclarativeRule, status_code=status.HTTP_201_CREATED)
async def propose_candidate_rule(
    payload: CreateRuleRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(Permission.RULES_WRITE)),
):
    """
    Proposes a new declarative detection rule.
    Strictly validates parameters against schema and rejects any executable code.
    Status is initialized as 'proposed'.
    """
    try:
        rule_schema = DeclarativeRule(
            tenant_id=auth.tenant_id,
            target_detector=payload.target_detector,
            title=payload.title,
            description=payload.description,
            parameters=payload.parameters,
            status="proposed",
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Rule validation error: {err}",
        )

    db_rule = DeclarativeRuleModel(
        rule_id=rule_schema.rule_id,
        tenant_id=auth.tenant_id,
        version=rule_schema.version,
        target_detector=rule_schema.target_detector,
        title=rule_schema.title,
        description=rule_schema.description,
        parameters=rule_schema.parameters,
        status=rule_schema.status,
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)

    ops_bus.publish(
        component="rules",
        event_type="rules.proposed",
        level="info",
        message=f"Proposed candidate rule '{db_rule.rule_id}': {db_rule.title}",
        tenant_id=auth.tenant_id,
        rule_id=db_rule.rule_id,
        metadata={"target_detector": db_rule.target_detector, "version": db_rule.version},
    )

    return DeclarativeRule(
        rule_id=db_rule.rule_id,
        tenant_id=db_rule.tenant_id,
        version=db_rule.version,
        target_detector=db_rule.target_detector,
        title=db_rule.title,
        description=db_rule.description,
        parameters=db_rule.parameters,
        status=db_rule.status,
        created_at=db_rule.created_at,
    )


@router.post("/{rule_id}/validate", response_model=ReplayValidationMetrics)
async def validate_candidate_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(Permission.RULES_VALIDATE)),
):
    """
    Replays the candidate rule against the standard incident evaluation suite.
    Calculates TP, FP, TN, FN, precision, recall, and F1.
    Sets status to 'validated' if criteria pass, or 'rejected' if false positives occur.
    """
    db_rule = db.query(DeclarativeRuleModel).filter(
        DeclarativeRuleModel.rule_id == rule_id
    ).first()

    if not db_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    if db_rule.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied across tenant boundary.")

    rule_schema = DeclarativeRule(
        rule_id=db_rule.rule_id,
        tenant_id=db_rule.tenant_id,
        version=db_rule.version,
        target_detector=db_rule.target_detector,
        title=db_rule.title,
        description=db_rule.description,
        parameters=db_rule.parameters,
        status=db_rule.status,
    )

    engine = ReplayValidationEngine()
    try:
        metrics = engine.validate_rule(rule_schema)
    except ValidationError as err:
        logger.info("Replay rejected invalid rule configuration for %s: %s", rule_id, err)
        issues = [
            f"{'.'.join(str(part) for part in issue.get('loc', ())) or 'rule'}: {issue.get('msg', 'invalid value')}"
            for issue in err.errors(include_input=False)
        ]
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Replay configuration is invalid: " + "; ".join(issues),
        ) from err
    except ValueError as err:
        logger.info("Replay rejected unsupported rule configuration for %s: %s", rule_id, err)
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Replay configuration is invalid: {err}",
        ) from err
    except RuntimeError as err:
        logger.exception("Replay dependencies unavailable for rule %s", rule_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Replay dependencies unavailable: {err}",
        ) from err
    except Exception as err:
        logger.exception("Unexpected replay validation failure for rule %s", rule_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Replay validation failed for rule '{rule_id}'. Check backend logs for details.",
        ) from err

    db_rule.status = rule_schema.status
    db_rule.validation_metrics = metrics.model_dump(mode="json")
    db.commit()

    ops_bus.publish(
        component="rules",
        event_type="rules.validation_completed",
        level="success" if metrics.passed_validation else "warn",
        message=f"Replay validation completed for '{rule_id}': {metrics.false_positives} FPs across {metrics.scenarios_evaluated} scenarios (status='{db_rule.status}')",
        tenant_id=auth.tenant_id,
        rule_id=rule_id,
        metadata={
            "passed": metrics.passed_validation,
            "false_positives": metrics.false_positives,
            "true_positives": metrics.true_positives,
            "status": db_rule.status,
        },
    )

    return metrics


@router.post("/{rule_id}/approve", response_model=DeclarativeRule)
async def approve_rule(
    rule_id: str,
    payload: ApprovalRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(Permission.RULES_APPROVE)),
):
    """
    Human/Policy approval gate.
    Requires the rule to have successfully passed replay validation (status='validated').
    """
    db_rule = db.query(DeclarativeRuleModel).filter(
        DeclarativeRuleModel.rule_id == rule_id
    ).first()

    if not db_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    if db_rule.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied across tenant boundary.")

    if db_rule.status not in ("validated", "approved"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot approve rule with status '{db_rule.status}'. Replay validation must pass first.",
        )

    rule_schema = DeclarativeRule(
        rule_id=db_rule.rule_id,
        tenant_id=db_rule.tenant_id,
        version=db_rule.version,
        target_detector=db_rule.target_detector,
        title=db_rule.title,
        description=db_rule.description,
        parameters=db_rule.parameters,
        status=db_rule.status,
        validation_metrics=ReplayValidationMetrics(**db_rule.validation_metrics) if db_rule.validation_metrics else None,
    )

    engine = ReplayValidationEngine()
    try:
        updated = engine.approve_candidate_rule(
            rule=rule_schema,
            decided_by=auth.tenant_id,
            rationale=payload.rationale,
            decision=payload.decision,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))

    db_rule.status = updated.status
    db_rule.approval_metadata = updated.approval.model_dump(mode="json") if updated.approval else None
    db.commit()

    ops_bus.publish(
        component="rules",
        event_type="rules.approved",
        level="success",
        message=f"Rule '{rule_id}' approved with rationale: {payload.rationale}",
        tenant_id=auth.tenant_id,
        rule_id=rule_id,
        metadata={"decision": payload.decision, "rationale": payload.rationale},
    )

    return updated


@router.post("/{rule_id}/activate", response_model=DeclarativeRule)
async def activate_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(Permission.RULES_ACTIVATE)),
):
    """
    Promotes an approved rule to active status.
    Active rules govern deterministic Fast Track detection.
    Precondition: Rule must be approved and have passing validation (0 false positives).
    """
    db_rule = db.query(DeclarativeRuleModel).filter(
        DeclarativeRuleModel.rule_id == rule_id
    ).first()

    if not db_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    if db_rule.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied across tenant boundary.")

    if db_rule.status not in ("approved", "disabled", "rolled_back"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot activate rule with status '{db_rule.status}'. Explicit approval is required first.",
        )

    # Invariant: A rule with false-positive validation results CANNOT be activated
    if db_rule.validation_metrics:
        vm = db_rule.validation_metrics
        if vm.get("false_positives", 0) > 0 or not vm.get("passed_validation", True):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Safety invariant violation: Cannot activate a rule that generated false positives during replay validation.",
            )

    db_rule.status = "active"

    # Audit trail & version preservation
    metadata = dict(db_rule.approval_metadata or {})
    history = list(metadata.get("history", []))
    history.append({
        "action": "activated",
        "by": auth.tenant_id,
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "active",
    })
    version_history = list(metadata.get("version_history", []))
    if not any(v.get("version") == db_rule.version for v in version_history):
        version_history.append({
            "version": db_rule.version,
            "parameters": db_rule.parameters,
            "status": "active",
            "validation_metrics": db_rule.validation_metrics,
            "created_at": db_rule.created_at.isoformat() if db_rule.created_at else None,
        })
    metadata["version_history"] = version_history
    metadata["history"] = history
    db_rule.approval_metadata = metadata

    db.commit()
    db.refresh(db_rule)

    # Invalidate runtime rule registry immediately so active rule evaluates on next event
    runtime_rule_registry.invalidate(auth.tenant_id)

    ops_bus.publish(
        component="rules",
        event_type="rules.activated",
        level="success",
        message=f"Rule '{rule_id}' activated into Fast Track detection registry (v{db_rule.version})",
        tenant_id=auth.tenant_id,
        rule_id=rule_id,
        rule_version=db_rule.version,
        metadata={"target_detector": db_rule.target_detector, "version": db_rule.version},
    )

    return DeclarativeRule(
        rule_id=db_rule.rule_id,
        tenant_id=db_rule.tenant_id,
        version=db_rule.version,
        target_detector=db_rule.target_detector,
        title=db_rule.title,
        description=db_rule.description,
        parameters=db_rule.parameters,
        status=db_rule.status,
        created_at=db_rule.created_at,
        validation_metrics=ReplayValidationMetrics(**db_rule.validation_metrics) if db_rule.validation_metrics else None,
        approval=ApprovalRecord(**db_rule.approval_metadata) if db_rule.approval_metadata else None,
    )


@router.post("/{rule_id}/disable", response_model=DeclarativeRule)
async def disable_rule(
    rule_id: str,
    payload: DisableRuleRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(Permission.RULES_DISABLE)),
):
    """
    Disables an active rule, withdrawing it from runtime evaluation immediately.
    Preserves audit history.
    """
    db_rule = db.query(DeclarativeRuleModel).filter(
        DeclarativeRuleModel.rule_id == rule_id
    ).first()

    if not db_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    if db_rule.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied across tenant boundary.")

    if db_rule.status not in ("active", "approved"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot disable rule with status '{db_rule.status}'. Only active or approved rules can be disabled.",
        )

    db_rule.status = "disabled"

    # Audit trail
    metadata = dict(db_rule.approval_metadata or {})
    history = list(metadata.get("history", []))
    history.append({
        "action": "disabled",
        "by": auth.tenant_id,
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "status": "disabled",
        "reason": payload.reason,
    })
    metadata["history"] = history
    db_rule.approval_metadata = metadata

    db.commit()
    db.refresh(db_rule)

    # Invalidate runtime rule registry immediately so runtime stops executing rule
    runtime_rule_registry.invalidate(auth.tenant_id)

    ops_bus.publish(
        component="rules",
        event_type="rules.disabled",
        level="warn",
        message=f"Rule '{rule_id}' disabled: {payload.reason}",
        tenant_id=auth.tenant_id,
        rule_id=rule_id,
        rule_version=db_rule.version,
        metadata={"reason": payload.reason},
    )

    return DeclarativeRule(
        rule_id=db_rule.rule_id,
        tenant_id=db_rule.tenant_id,
        version=db_rule.version,
        target_detector=db_rule.target_detector,
        title=db_rule.title,
        description=db_rule.description,
        parameters=db_rule.parameters,
        status=db_rule.status,
        created_at=db_rule.created_at,
        validation_metrics=ReplayValidationMetrics(**db_rule.validation_metrics) if db_rule.validation_metrics else None,
        approval=ApprovalRecord(**db_rule.approval_metadata) if db_rule.approval_metadata else None,
    )


@router.post("/{rule_id}/rollback", response_model=DeclarativeRule)
async def rollback_rule(
    rule_id: str,
    payload: RollbackRuleRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(Permission.RULES_ROLLBACK)),
):
    """
    Rolls back a rule to a previously approved version or safely reverts it.
    Preserves version lineage without silently overwriting history (increments version).
    Immediately updates runtime detection behavior.
    """
    db_rule = db.query(DeclarativeRuleModel).filter(
        DeclarativeRuleModel.rule_id == rule_id
    ).first()

    if not db_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    if db_rule.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied across tenant boundary.")

    metadata = dict(db_rule.approval_metadata or {})
    version_history = list(metadata.get("version_history", []))
    history = list(metadata.get("history", []))

    current_ver = db_rule.version

    # Preserve current state before rollback
    if not any(v.get("version") == current_ver for v in version_history):
        version_history.append({
            "version": current_ver,
            "parameters": db_rule.parameters,
            "status": db_rule.status,
            "validation_metrics": db_rule.validation_metrics,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        })

    # Find target version snapshot if requested
    target_snapshot = None
    if payload.target_version is not None:
        for snap in version_history:
            if snap.get("version") == payload.target_version:
                target_snapshot = snap
                break
        if not target_snapshot:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Target version {payload.target_version} does not exist in rule's approved version history.",
            )
    elif len(version_history) > 1:
        # Use previous version snapshot
        target_snapshot = version_history[-2]

    # Increment version to guarantee auditable version lineage
    new_ver = current_ver + 1
    db_rule.version = new_ver

    if target_snapshot:
        db_rule.parameters = target_snapshot.get("parameters", db_rule.parameters)
        db_rule.status = "active"
        target_v_num = target_snapshot.get("version")
    else:
        # If no previous snapshot, roll back to disabled state
        db_rule.status = "disabled"
        target_v_num = current_ver

    history.append({
        "action": "rolled_back",
        "from_version": current_ver,
        "to_version": new_ver,
        "restored_version_parameters": target_v_num,
        "by": auth.tenant_id,
        "at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "rationale": payload.rationale,
        "status": db_rule.status,
    })

    metadata["version_history"] = version_history
    metadata["history"] = history
    db_rule.approval_metadata = metadata

    db.commit()
    db.refresh(db_rule)

    # Invalidate runtime rule registry immediately so runtime behavior changes
    runtime_rule_registry.invalidate(auth.tenant_id)

    ops_bus.publish(
        component="rules",
        event_type="rules.rolled_back",
        level="warn",
        message=f"Rule '{rule_id}' rolled back from v{current_ver} to v{new_ver}: {payload.rationale}",
        tenant_id=auth.tenant_id,
        rule_id=rule_id,
        rule_version=new_ver,
        metadata={"from_version": current_ver, "to_version": new_ver, "rationale": payload.rationale, "status": db_rule.status},
    )

    return DeclarativeRule(
        rule_id=db_rule.rule_id,
        tenant_id=db_rule.tenant_id,
        version=db_rule.version,
        target_detector=db_rule.target_detector,
        title=db_rule.title,
        description=db_rule.description,
        parameters=db_rule.parameters,
        status=db_rule.status,
        created_at=db_rule.created_at,
        validation_metrics=ReplayValidationMetrics(**db_rule.validation_metrics) if db_rule.validation_metrics else None,
        approval=ApprovalRecord(**db_rule.approval_metadata) if db_rule.approval_metadata else None,
    )


@router.get("/{rule_id}/history", response_model=Dict[str, Any])
async def get_rule_history(
    rule_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Returns the complete version lineage and lifecycle audit history for a rule.
    """
    db_rule = db.query(DeclarativeRuleModel).filter(
        DeclarativeRuleModel.rule_id == rule_id
    ).first()

    if not db_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    if db_rule.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied across tenant boundary.")

    metadata = db_rule.approval_metadata or {}
    return {
        "rule_id": db_rule.rule_id,
        "current_version": db_rule.version,
        "current_status": db_rule.status,
        "history": metadata.get("history", []),
        "version_history": metadata.get("version_history", []),
    }


@router.get("", response_model=List[DeclarativeRule])
async def list_rules(
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Lists rules belonging to the authenticated tenant.
    """
    query = db.query(DeclarativeRuleModel).filter(DeclarativeRuleModel.tenant_id == auth.tenant_id)
    if status_filter:
        query = query.filter(DeclarativeRuleModel.status == status_filter)

    rules = query.order_by(DeclarativeRuleModel.created_at.desc()).all()
    return [
        DeclarativeRule(
            rule_id=r.rule_id,
            tenant_id=r.tenant_id,
            version=r.version,
            target_detector=r.target_detector,
            title=r.title,
            description=r.description,
            parameters=r.parameters,
            status=r.status,
            created_at=r.created_at,
            validation_metrics=ReplayValidationMetrics(**r.validation_metrics) if r.validation_metrics else None,
            approval=ApprovalRecord(**r.approval_metadata) if r.approval_metadata else None,
        )
        for r in rules
    ]


@router.get("/{rule_id}", response_model=DeclarativeRule)
async def get_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(get_current_auth),
):
    """
    Retrieves a single rule by ID.
    """
    db_rule = db.query(DeclarativeRuleModel).filter(
        DeclarativeRuleModel.rule_id == rule_id
    ).first()

    if not db_rule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule '{rule_id}' not found.")

    if db_rule.tenant_id != auth.tenant_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied across tenant boundary.")

    return DeclarativeRule(
        rule_id=db_rule.rule_id,
        tenant_id=db_rule.tenant_id,
        version=db_rule.version,
        target_detector=db_rule.target_detector,
        title=db_rule.title,
        description=db_rule.description,
        parameters=db_rule.parameters,
        status=db_rule.status,
        created_at=db_rule.created_at,
        validation_metrics=ReplayValidationMetrics(**db_rule.validation_metrics) if db_rule.validation_metrics else None,
        approval=ApprovalRecord(**db_rule.approval_metadata) if db_rule.approval_metadata else None,
    )


from typing import Literal

class GenerateRuleFromPromptRequest(BaseModel):
    prompt: str = Field(..., min_length=5, max_length=1000, description="Natural language description of detection rule")
    severity: Literal["low", "medium", "high", "critical"] = "high"
    target_service: Optional[str] = None


class GenerateRuleFromPromptResponse(BaseModel):
    rule: DeclarativeRule
    explanation: str
    suggested_test_event: Dict[str, Any]


@router.post("/generate-from-prompt", response_model=GenerateRuleFromPromptResponse, status_code=status.HTTP_201_CREATED)
async def generate_rule_from_prompt(
    payload: GenerateRuleFromPromptRequest,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission(Permission.RULES_WRITE)),
):
    """
    Translates an analyst natural language description into a strictly validated
    declarative detection rule (AST condition tree).
    Validates parameters deterministically against GenericDeclarativeRuleDefinition.
    Persists the candidate rule with status 'proposed' awaiting scenario replay.
    """
    prompt_lower = payload.prompt.lower()
    
    # Deterministic pattern parser mapping plain English to AST schemas
    # 1. Failed login / Auth threshold
    if any(k in prompt_lower for k in ["auth", "login", "password", "spray", "credential", "failed"]):
        title = f"Threshold Detection: {payload.prompt[:50]}"
        description = f"AI synthesized rule for: {payload.prompt}"
        rule_params = {
            "rule_type": "threshold",
            "group_by": ["tenant_id", "source_resource"],
            "window_seconds": 60.0,
            "severity": payload.severity,
            "conditions": [
                {"field": "event_type", "operator": "equals", "value": "auth.login.failed"}
            ],
            "threshold": {
                "count": 5,
                "time_window_seconds": 60.0
            }
        }
        explanation = "Detects bursts of 5 or more failed login events from the same source IP/entity within a 60-second sliding window."
        test_event = {
            "event_type": "auth.login.failed",
            "service_id": payload.target_service or "auth-service",
            "source_resource": "198.51.100.24",
            "severity": payload.severity
        }

    # 2. Cross-service or data exfiltration / DB egress
    elif any(k in prompt_lower for k in ["exfiltration", "egress", "database", "db", "bulk", "export", "download"]):
        title = f"Data Exfiltration Rule: {payload.prompt[:50]}"
        description = f"AI synthesized rule for: {payload.prompt}"
        rule_params = {
            "rule_type": "threshold",
            "group_by": ["tenant_id", "service_id"],
            "window_seconds": 300.0,
            "severity": payload.severity,
            "conditions": [
                {"field": "event_type", "operator": "contains", "value": "exfiltration"}
            ],
            "threshold": {
                "count": 3,
                "time_window_seconds": 300.0
            }
        }
        explanation = "Detects repeated high-volume data exfiltration signals from microservices within a 5-minute sliding window."
        test_event = {
            "event_type": "data.exfiltration.detected",
            "service_id": payload.target_service or "database-service",
            "source_resource": "db-node-01",
            "severity": payload.severity
        }

    # 3. Default generic service threshold
    else:
        title = f"Anomaly Detection: {payload.prompt[:50]}"
        description = f"AI synthesized rule for: {payload.prompt}"
        svc = payload.target_service or "api-service"
        rule_params = {
            "rule_type": "threshold",
            "group_by": ["tenant_id", "service_id"],
            "window_seconds": 120.0,
            "severity": payload.severity,
            "conditions": [
                {"field": "service_id", "operator": "equals", "value": svc}
            ],
            "threshold": {
                "count": 10,
                "time_window_seconds": 120.0
            }
        }
        explanation = f"Monitors {svc} for abnormal burst rates exceeding 10 events within a 2-minute window."
        test_event = {
            "event_type": "system.anomaly",
            "service_id": svc,
            "severity": payload.severity
        }

    # Validate against declarative rule schema
    try:
        rule_schema = DeclarativeRule(
            tenant_id=auth.tenant_id,
            target_detector="generic.declarative",
            title=title,
            description=description,
            parameters=rule_params,
            status="proposed",
        )
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Synthesized rule parameter validation failed: {err}",
        )

    db_rule = DeclarativeRuleModel(
        rule_id=rule_schema.rule_id,
        tenant_id=auth.tenant_id,
        version=rule_schema.version,
        target_detector=rule_schema.target_detector,
        title=rule_schema.title,
        description=rule_schema.description,
        parameters=rule_schema.parameters,
        status="proposed",
        created_at=rule_schema.created_at,
        validation_metrics=None,
        approval_metadata=None,
    )
    db.add(db_rule)
    db.commit()
    db.refresh(db_rule)

    return GenerateRuleFromPromptResponse(
        rule=rule_schema,
        explanation=explanation,
        suggested_test_event=test_event,
    )
