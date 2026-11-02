"""
REST API for Phase 2: Threat Intelligence & IOC Management.

Provides endpoints for:
1. Registering and managing Indicators of Compromise (IOCs).
2. Querying stored telemetry for indicators with microservice blast radius analysis.
3. MITRE ATT&CK matrix coverage calculations.
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.core.auth import AuthContext, Permission, require_permission
from backend.db.session import get_db
from backend.schemas.threat_intel import (
    IocType,
    MitreCoverageResponse,
    ThreatIntelIocCreateRequest,
    ThreatIntelIocResponse,
    ThreatIntelMatchRequest,
    ThreatIntelMatchResult,
)
from backend.threat_intel.matcher import ThreatIntelMatcher
from backend.threat_intel.registry import ThreatIntelRegistry

logger = logging.getLogger("cyber_engine.api.threat_intel")

router = APIRouter(prefix="/api/v1/threat-intelligence", tags=["Threat Intelligence"])


@router.get("", response_model=List[ThreatIntelIocResponse])
async def list_iocs(
    ioc_type: Optional[IocType] = None,
    is_active: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(require_permission(Permission.THREAT_INTEL_READ)),
    db: Session = Depends(get_db),
):
    """
    Lists threat intelligence indicators of compromise for the authenticated tenant.
    Requires permission: threat_intel:read
    """
    registry = ThreatIntelRegistry(db)
    return registry.list_iocs(
        tenant_id=auth.tenant_id,
        ioc_type=ioc_type,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )


@router.post("", response_model=ThreatIntelIocResponse, status_code=status.HTTP_201_CREATED)
async def create_ioc(
    payload: ThreatIntelIocCreateRequest,
    auth: AuthContext = Depends(require_permission(Permission.THREAT_INTEL_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Registers a new Indicator of Compromise (IOC) in the tenant's threat intelligence registry.
    Requires permission: threat_intel:write
    """
    registry = ThreatIntelRegistry(db)
    created = registry.create_ioc(tenant_id=auth.tenant_id, payload=payload)
    return created


@router.get("/mitre-coverage", response_model=MitreCoverageResponse)
async def get_mitre_coverage(
    auth: AuthContext = Depends(require_permission(Permission.THREAT_INTEL_READ)),
    db: Session = Depends(get_db),
):
    """
    Calculates tenant MITRE ATT&CK matrix coverage across detectors, rules, and active findings.
    Requires permission: threat_intel:read
    """
    matcher = ThreatIntelMatcher(db)
    return matcher.get_mitre_coverage(tenant_id=auth.tenant_id)


@router.post("/match", response_model=ThreatIntelMatchResult)
async def match_telemetry_against_iocs(
    payload: ThreatIntelMatchRequest,
    auth: AuthContext = Depends(require_permission(Permission.THREAT_INTEL_READ)),
    db: Session = Depends(get_db),
):
    """
    Cross-references an indicator, query pattern, or keyword against stored microservice telemetry
    and active IOC records. Identifies affected microservices and matched ATT&CK techniques.
    Requires permission: threat_intel:read
    """
    matcher = ThreatIntelMatcher(db)
    return matcher.match_telemetry(
        tenant_id=auth.tenant_id,
        query=payload.query,
        time_window_hours=payload.time_window_hours,
        limit=payload.limit,
    )


@router.get("/{ioc_id}", response_model=ThreatIntelIocResponse)
async def get_ioc(
    ioc_id: str,
    auth: AuthContext = Depends(require_permission(Permission.THREAT_INTEL_READ)),
    db: Session = Depends(get_db),
):
    """
    Retrieves a specific Indicator of Compromise.
    Requires permission: threat_intel:read
    """
    registry = ThreatIntelRegistry(db)
    ioc = registry.get_ioc(tenant_id=auth.tenant_id, ioc_id=ioc_id)
    if not ioc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat intelligence IOC '{ioc_id}' not found",
        )
    return ioc


@router.delete("/{ioc_id}", response_model=ThreatIntelIocResponse)
async def deactivate_ioc(
    ioc_id: str,
    auth: AuthContext = Depends(require_permission(Permission.THREAT_INTEL_WRITE)),
    db: Session = Depends(get_db),
):
    """
    Deactivates an Indicator of Compromise.
    Requires permission: threat_intel:write
    """
    registry = ThreatIntelRegistry(db)
    deactivated = registry.deactivate_ioc(tenant_id=auth.tenant_id, ioc_id=ioc_id)
    if not deactivated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat intelligence IOC '{ioc_id}' not found",
        )
    return deactivated

