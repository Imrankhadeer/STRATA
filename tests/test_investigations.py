"""
Tests for CYBER ENGINE Milestone 3: Deep-Investigation Path.

Covers:
1. Evidence collection and chronological context assembly across services.
2. MockInvestigator: Grounded hypotheses, citations, and candidate rule proposals.
3. MetaModelInvestigator: Official Meta API formatting, JSON parsing, and graceful fallback.
4. OpenAICompatibleInvestigator: Generic provider support.
5. Safety Gates: Candidate rules remain in proposed status and cannot auto-execute.
6. REST API: Triggering, retrieval, listing, and strict tenant boundary isolation.
"""

import pytest
import json
from unittest.mock import patch, MagicMock, AsyncMock
import httpx

from tests.conftest import TEST_APP_ID, RAW_TEST_API_KEY, TEST_TENANT_ID
from cyber_engine import CyberEngine
from scenarios.run_scenario import run_synthetic_scenario
from backend.models import SecurityFinding, InvestigationReport, Tenant, ApiKey
from backend.core.auth import hash_api_key
from backend.investigation.collector import EvidenceCollector
from backend.investigation.adapters import (
    MockInvestigator,
    MetaModelInvestigator,
    OpenAICompatibleInvestigator,
    _clean_json_content,
)
from backend.investigation.factory import get_investigator
from backend.schemas.investigation import InvestigationContext


@pytest.fixture
def populated_scenario(client, db_session):
    """Executes the synthetic scenario once to generate multi-service events and findings."""
    sdk = CyberEngine(
        api_key=RAW_TEST_API_KEY,
        app=TEST_APP_ID,
        endpoint="http://testserver",
    )
    sdk._client = client
    run_synthetic_scenario(sdk)

    finding = db_session.query(SecurityFinding).filter(
        SecurityFinding.detector_id == "detector.cross_service.exfiltration"
    ).first()
    assert finding is not None
    return finding


@pytest.mark.asyncio
async def test_evidence_collector_assembles_context(populated_scenario, db_session):
    finding = populated_scenario
    collector = EvidenceCollector(db_session)
    context = collector.assemble_context(finding.finding_id)

    assert context is not None
    assert context.finding_id == finding.finding_id
    assert context.tenant_id == TEST_TENANT_ID
    assert context.trace_id is not None

    # Verify that events from all three services in the exfiltration trace are captured
    assert len(context.timeline_events) == 3
    service_names = {e["service_id"] for e in context.timeline_events}
    assert service_names == {"api-service", "worker-service", "database-service"}

    # Verify chronological ordering
    timestamps = [e["timestamp"] for e in context.timeline_events]
    assert timestamps == sorted(timestamps)


@pytest.mark.asyncio
async def test_mock_investigator_produces_grounded_hypotheses(populated_scenario, db_session):
    finding = populated_scenario
    collector = EvidenceCollector(db_session)
    context = collector.assemble_context(finding.finding_id)

    investigator = MockInvestigator()
    report = await investigator.investigate(context)

    assert report.verdict == "confirmed_threat"
    assert len(report.hypotheses) >= 2

    # Verify hypothesis types (malicious vs benign alternative)
    natures = {h.nature for h in report.hypotheses}
    assert "malicious" in natures
    assert "benign" in natures

    # Verify supporting evidence citations contain actual event IDs
    for h in report.hypotheses:
        assert len(h.supporting_evidence) > 0
        for cite in h.supporting_evidence:
            assert cite.event_id is not None
            assert cite.service_id in ("api-service", "worker-service", "database-service")

    # Verify Safety Gate: Candidate rules are strictly proposals
    assert len(report.candidate_rules) >= 1
    for rule in report.candidate_rules:
        assert rule.status == "proposed"
        assert rule.rationale != ""

    assert len(report.recommended_mitigations) > 0


@pytest.mark.asyncio
async def test_meta_model_investigator_success_mock(populated_scenario, db_session):
    finding = populated_scenario
    collector = EvidenceCollector(db_session)
    context = collector.assemble_context(finding.finding_id)

    meta_mock_response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps({
                        "verdict": "confirmed_threat",
                        "summary": "Coordinated multi-tier exfiltration confirmed by Meta Model.",
                        "hypotheses": [
                            {
                                "title": "Targeted Exfiltration via Internal Endpoint",
                                "description": "Attacker invoked internal export and dumped table.",
                                "likelihood": "high",
                                "nature": "malicious",
                                "supporting_evidence": [
                                    {
                                        "event_id": context.timeline_events[0]["event_id"],
                                        "service_id": "api-service",
                                        "timestamp": context.timeline_events[0]["timestamp"],
                                        "relevance": "Unusual internal endpoint call",
                                    }
                                ],
                            }
                        ],
                        "candidate_rules": [
                            {
                                "title": "Block internal export from non-admin IP",
                                "description": "Detects anomalous source IP on export routes.",
                                "logic_type": "attribute_match",
                                "proposed_thresholds": {},
                                "rationale": "Prevents unauthorized access from unlisted IPs.",
                            }
                        ],
                        "recommended_mitigations": ["Isolate client IP", "Rotate keys"],
                    })
                }
            }
        ]
    }

    investigator = MetaModelInvestigator(
        api_key="meta_test_api_key_123",
        base_url="https://api.llama.com/v1",
        model="Llama-3.3-70B-Instruct",
    )

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_resp = MagicMock()
        mock_resp.raise_for_status.return_value = None
        mock_resp.json.return_value = meta_mock_response
        mock_post.return_value = mock_resp

        report = await investigator.investigate(context)

        assert report.verdict == "confirmed_threat"
        assert report.investigator_provider == "meta"
        assert report.investigator_model == "Llama-3.3-70B-Instruct"
        assert len(report.hypotheses) == 1
        assert report.hypotheses[0].nature == "malicious"
        # Safety gate invariant maintained
        assert report.candidate_rules[0].status == "proposed"


@pytest.mark.asyncio
async def test_meta_model_investigator_markdown_json_cleaning():
    raw_markdown = "```json\n{\"verdict\": \"likely_benign\", \"summary\": \"Clean test\"}\n```"
    cleaned = _clean_json_content(raw_markdown)
    parsed = json.loads(cleaned)
    assert parsed["verdict"] == "likely_benign"


@pytest.mark.asyncio
async def test_meta_model_investigator_graceful_fallback(populated_scenario, db_session):
    """
    CRITICAL ARCHITECTURAL SAFEGUARD:
    If the external Meta Model API returns an error or timeout, the engine must
    gracefully fallback to deterministic local analysis without crashing.
    """
    finding = populated_scenario
    collector = EvidenceCollector(db_session)
    context = collector.assemble_context(finding.finding_id)

    investigator = MetaModelInvestigator(
        api_key="meta_test_bad_key",
        base_url="https://api.llama.com/v1",
        model="Llama-3.3-70B-Instruct",
    )

    with patch("httpx.AsyncClient.post", side_effect=httpx.ConnectTimeout("Connection to Meta API timed out")):
        # Must NOT raise exception
        report = await investigator.investigate(context)
        assert report is not None
        assert report.verdict == "confirmed_threat"
        assert "fallback" in report.summary.lower()


def test_investigator_factory():
    mock_inv = get_investigator("mock")
    assert isinstance(mock_inv, MockInvestigator)

    meta_inv = get_investigator("meta")
    assert isinstance(meta_inv, MetaModelInvestigator)

    openai_inv = get_investigator("openai_compatible")
    assert isinstance(openai_inv, OpenAICompatibleInvestigator)


def test_investigation_api_endpoints_and_persistence(populated_scenario, client, auth_headers, db_session):
    finding = populated_scenario

    # 1. Trigger investigation via POST
    response = client.post(
        f"/api/v1/investigations/{finding.finding_id}",
        headers=auth_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == finding.finding_id
    assert data["verdict"] == "confirmed_threat"
    investigation_id = data["investigation_id"]

    # 2. Verify report persisted in database
    db_report = db_session.query(InvestigationReport).filter(
        InvestigationReport.investigation_id == investigation_id
    ).first()
    assert db_report is not None
    assert db_report.finding_id == finding.finding_id

    # 3. Retrieve investigation by ID via GET
    get_res = client.get(
        f"/api/v1/investigations/{investigation_id}",
        headers=auth_headers,
    )
    assert get_res.status_code == 200
    assert get_res.json()["investigation_id"] == investigation_id

    # 4. List investigations for the finding
    list_res = client.get(
        f"/api/v1/investigations/finding/{finding.finding_id}",
        headers=auth_headers,
    )
    assert list_res.status_code == 200
    reports = list_res.json()
    assert len(reports) >= 1
    assert reports[0]["investigation_id"] == investigation_id


def test_tenant_boundary_isolation_on_investigations(populated_scenario, client, db_session):
    finding = populated_scenario

    # Create a second tenant with its own API key if not already present
    tenant_beta = db_session.query(Tenant).filter(Tenant.id == "tenant-beta").first()
    if not tenant_beta:
        tenant_beta = Tenant(id="tenant-beta", name="Beta Corp", is_active=True)
        db_session.add(tenant_beta)
        db_session.flush()
    raw_beta_key = "ce_live_beta_secret_key_9999"
    api_key_beta = ApiKey(
        id="key-beta-001",
        tenant_id="tenant-beta",
        app_id="beta-app",
        key_hash=hash_api_key(raw_beta_key),
        key_prefix="ce_live_",
        is_active=True,
    )
    db_session.add(api_key_beta)
    db_session.commit()

    beta_headers = {"Authorization": f"Bearer {raw_beta_key}"}

    # Tenant Beta attempts to trigger investigation on Tenant Alpha's finding -> 403 Forbidden
    cross_tenant_res = client.post(
        f"/api/v1/investigations/{finding.finding_id}",
        headers=beta_headers,
    )
    assert cross_tenant_res.status_code == 403
    assert "Forbidden" in cross_tenant_res.json()["detail"]

    # Non-existent finding -> 404 Not Found
    not_found_res = client.post(
        "/api/v1/investigations/non-existent-finding-uuid",
        headers=beta_headers,
    )
    assert not_found_res.status_code == 404

