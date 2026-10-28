import uuid
from typing import Dict, Any, Optional
from cyber_engine import CyberEngine


class DatabaseServiceSimulator:
    """
    Simulates database queries, record access, and sensitive data modifications.
    """
    def __init__(self, client: CyberEngine):
        self.client = client
        self.service_name = "database-service"

    def record_access(self, table: str, operation: str, rows_affected: int, trace_id: str, is_bulk_exfil: bool = False) -> None:
        severity = "high" if is_bulk_exfil else "info"
        event_type = "db.bulk_query" if is_bulk_exfil else "db.query_executed"

        self.client.emit(
            event_type=event_type,
            severity=severity,
            service=self.service_name,
            source_resource="worker-service",
            target_resource=f"pg_cluster:{table}",
            trace_id=trace_id,
            attributes={
                "table": table,
                "operation": operation,
                "rows_affected": rows_affected,
                "query_duration_ms": 3200 if is_bulk_exfil else 45,
                "is_sensitive_table": table in ["users", "credit_cards", "tokens"]
            }
        )
