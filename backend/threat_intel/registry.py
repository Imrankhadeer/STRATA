"""
Threat Intelligence Registry for Ternline Phase 2.

Manages tenant-scoped Indicators of Compromise (IOCs) including attacker IPs,
malicious domains, payload hashes, suspicious user-agents, and unauthorized database query patterns.
"""

import datetime
import logging
import uuid
from typing import List, Optional

from sqlalchemy.orm import Session

from backend.models import ThreatIntelIocModel
from backend.schemas.threat_intel import (
    IocConfidence,
    IocSeverity,
    IocType,
    ThreatIntelIocCreateRequest,
    ThreatIntelIocResponse,
)

logger = logging.getLogger("cyber_engine.threat_intel.registry")


class ThreatIntelRegistry:
    """
    CRUD management for tenant-isolated Indicators of Compromise.
    """

    def __init__(self, db: Session):
        self.db = db

    def create_ioc(
        self,
        tenant_id: str,
        payload: ThreatIntelIocCreateRequest,
    ) -> ThreatIntelIocModel:
        now = datetime.datetime.now(datetime.timezone.utc)
        ioc_id = f"ioc-{uuid.uuid4().hex[:10]}"

        expires_at = None
        if payload.expires_in_days:
            expires_at = now + datetime.timedelta(days=payload.expires_in_days)

        model = ThreatIntelIocModel(
            ioc_id=ioc_id,
            tenant_id=tenant_id,
            ioc_type=payload.ioc_type.value,
            value=payload.value.strip(),
            threat_actor=payload.threat_actor,
            description=payload.description,
            severity=payload.severity.value,
            confidence=payload.confidence.value,
            mitre_tactics=payload.mitre_tactics or [],
            mitre_techniques=payload.mitre_techniques or [],
            is_active=True,
            source=payload.source,
            expires_at=expires_at,
            created_at=now,
            updated_at=now,
        )
        self.db.add(model)
        self.db.commit()
        self.db.refresh(model)

        logger.info(
            "ThreatIntelRegistry: Registered IOC '%s' (type: %s, value: %s) for tenant '%s'",
            ioc_id,
            model.ioc_type,
            model.value,
            tenant_id,
        )
        return model

    def get_ioc(self, tenant_id: str, ioc_id: str) -> Optional[ThreatIntelIocModel]:
        return (
            self.db.query(ThreatIntelIocModel)
            .filter(
                ThreatIntelIocModel.ioc_id == ioc_id,
                ThreatIntelIocModel.tenant_id == tenant_id,
            )
            .first()
        )

    def list_iocs(
        self,
        tenant_id: str,
        ioc_type: Optional[IocType] = None,
        is_active: Optional[bool] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[ThreatIntelIocModel]:
        query = self.db.query(ThreatIntelIocModel).filter(
            ThreatIntelIocModel.tenant_id == tenant_id
        )
        if ioc_type:
            query = query.filter(ThreatIntelIocModel.ioc_type == ioc_type.value)
        if is_active is not None:
            query = query.filter(ThreatIntelIocModel.is_active == is_active)

        return (
            query.order_by(ThreatIntelIocModel.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    def deactivate_ioc(self, tenant_id: str, ioc_id: str) -> Optional[ThreatIntelIocModel]:
        model = self.get_ioc(tenant_id, ioc_id)
        if not model:
            return None

        model.is_active = False
        model.updated_at = datetime.datetime.now(datetime.timezone.utc)
        self.db.commit()
        self.db.refresh(model)
        logger.info("ThreatIntelRegistry: Deactivated IOC '%s' for tenant '%s'", ioc_id, tenant_id)
        return model

    def delete_ioc(self, tenant_id: str, ioc_id: str) -> bool:
        model = self.get_ioc(tenant_id, ioc_id)
        if not model:
            return False

        self.db.delete(model)
        self.db.commit()
        logger.info("ThreatIntelRegistry: Deleted IOC '%s' for tenant '%s'", ioc_id, tenant_id)
        return True

