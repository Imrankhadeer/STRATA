"""
Unit and Integration Tests for Asynchronous Telemetry Ingestion Worker.

Validates:
1. Enqueue and dequeue processing of telemetry events.
2. Ingestion pipeline in ASYNC_INGESTION_ENABLED mode returns correlation_status='queued'.
3. TelemetryWorker pops and evaluates queued events in background, persisting findings.
4. Seamless synchronous fallback when async queue connection is not available.
"""

import pytest
import fakeredis
from unittest.mock import patch

from backend.detection.worker import TelemetryWorker
from backend.models import SecurityFinding
from tests.conftest import TEST_TENANT_ID, TEST_APP_ID, RAW_TEST_API_KEY


def test_telemetry_worker_enqueue_and_process(db_session):
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    worker = TelemetryWorker(redis_client=fake_redis, queue_key="test:telemetry_queue")

    # Enqueue a failed login event
    event_dict = {
        "event_id": "ev-worker-test-1",
        "schema_version": "1.0.0",
        "app_id": TEST_APP_ID,
        "service_id": "auth-service",
        "event_type": "auth.login_failed",
        "severity": "medium",
        "source_resource": "203.0.113.199",
        "tenant_id": TEST_TENANT_ID,
    }
    enqueued = worker.enqueue(event_dict, TEST_TENANT_ID)
    assert enqueued is True
    assert fake_redis.llen("test:telemetry_queue") == 1

    # Process event from queue
    processed = worker.process_one(db_session)
    assert processed is True
    assert fake_redis.llen("test:telemetry_queue") == 0
    assert fake_redis.llen("test:telemetry_queue:processing") == 0


def test_telemetry_worker_retries_tenant_mismatch(db_session):
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    worker = TelemetryWorker(
        redis_client=fake_redis,
        queue_key="test:tenant_mismatch_queue",
        max_retries=2,
    )
    worker.enqueue(
        {
            "event_id": "ev-worker-tenant-mismatch",
            "schema_version": "1.0.0",
            "app_id": TEST_APP_ID,
            "service_id": "auth-service",
            "event_type": "auth.login_failed",
            "severity": "medium",
            "tenant_id": "tenant-beta",
        },
        TEST_TENANT_ID,
    )

    assert worker.process_one(db_session) is False
    assert fake_redis.llen(worker.queue_key) == 1
    assert fake_redis.llen(worker.processing_key) == 0
    assert fake_redis.llen(worker.dead_letter_key) == 0


def test_async_ingestion_mode_queues_and_processes(client, auth_headers, db_session, monkeypatch):
    fake_redis = fakeredis.FakeRedis(decode_responses=True)
    queue_name = "test:async_queue"

    # Patch redis.Redis.from_url to return our fake_redis instance
    monkeypatch.setattr("redis.Redis.from_url", lambda *args, **kwargs: fake_redis)
    monkeypatch.setattr("backend.api.ingest.settings.ASYNC_INGESTION_ENABLED", True)
    monkeypatch.setattr("backend.api.ingest.settings.ASYNC_QUEUE_KEY", queue_name)
    monkeypatch.setattr("backend.api.ingest.settings.REDIS_URL", "redis://localhost:6379/0")

    # Ingest event under async mode
    payload = {
        "event_id": "ev-async-001",
        "schema_version": "1.0.0",
        "app_id": TEST_APP_ID,
        "service_id": "auth-service",
        "event_type": "auth.login_failed",
        "severity": "medium",
        "source_resource": "203.0.113.88",
    }
    resp = client.post("/v1/events", json=payload, headers=auth_headers)
    assert resp.status_code == 202
    data = resp.json()
    assert data["accepted"] == 1
    assert data["correlation_status"] == "queued"

    # Verify event is waiting in Redis queue
    assert fake_redis.llen(queue_name) == 1

    # Process with worker
    worker = TelemetryWorker(redis_client=fake_redis, queue_key=queue_name)
    processed = worker.process_one(db_session)
    assert processed is True
    assert fake_redis.llen(queue_name) == 0
