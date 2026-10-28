import pytest
from datetime import datetime, timezone
import uuid
import httpx
from cyber_engine import CyberEngine, CyberEngineError, IngestResult
from tests.conftest import TEST_APP_ID, RAW_TEST_API_KEY


def test_sdk_emit_single_event(client, monkeypatch):
    """Verifies Python SDK can construct and emit an event to the backend."""
    sdk = CyberEngine(
        api_key=RAW_TEST_API_KEY,
        app=TEST_APP_ID,
        service="payments-service",
        endpoint="http://testserver",
    )
    # Route SDK client requests through FastAPI TestClient transport
    sdk._client = client

    result = sdk.emit(
        event_type="payment.processed",
        severity="info",
        source_resource="customer:c_9941",
        target_resource="order:ord_5521",
        trace_id="trace-pay-1",
        attributes={"amount_usd": 149.99, "currency": "USD"}
    )

    assert isinstance(result, IngestResult)
    assert result.accepted == 1
    assert result.duplicates == 0
    assert len(result.event_ids) == 1

    sdk.close()


def test_sdk_validation_errors():
    """Verifies SDK constructor enforces non-empty API keys and apps."""
    with pytest.raises(ValueError):
        CyberEngine(api_key="", app="my-app")

    with pytest.raises(ValueError):
        CyberEngine(api_key="ce_live_123", app="")


def test_sdk_context_manager():
    """Verifies SDK clean shutdown and context manager support."""
    with CyberEngine(
        api_key=RAW_TEST_API_KEY,
        app=TEST_APP_ID,
        buffered=False,
    ) as engine:
        assert engine.app == TEST_APP_ID
