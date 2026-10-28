import uuid
from typing import Dict, Any, Optional
from cyber_engine import CyberEngine


class ApiServiceSimulator:
    """
    Simulates the public-facing API service:
    Handles authentication requests, user sessions, and incoming API calls.
    """
    def __init__(self, client: CyberEngine):
        self.client = client
        self.service_name = "api-service"

    def handle_login(self, username: str, client_ip: str, success: bool, trace_id: Optional[str] = None) -> str:
        trace_id = trace_id or f"trace-{uuid.uuid4()}"
        event_type = "auth.login_success" if success else "auth.login_failed"
        severity = "info" if success else "low"

        self.client.emit(
            event_type=event_type,
            severity=severity,
            service=self.service_name,
            source_resource=client_ip,
            target_resource=f"user:{username}",
            trace_id=trace_id,
            attributes={
                "username": username,
                "client_ip": client_ip,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "result": "success" if success else "invalid_credentials"
            }
        )
        return trace_id

    def handle_request(self, endpoint: str, client_ip: str, method: str = "GET", trace_id: Optional[str] = None) -> str:
        trace_id = trace_id or f"trace-{uuid.uuid4()}"
        self.client.emit(
            event_type="http.request",
            severity="info",
            service=self.service_name,
            source_resource=client_ip,
            target_resource=endpoint,
            trace_id=trace_id,
            attributes={
                "method": method,
                "endpoint": endpoint,
                "status_code": 200,
            }
        )
        return trace_id
