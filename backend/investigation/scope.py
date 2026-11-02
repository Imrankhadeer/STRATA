"""
Scope and Relevancy Verification for CYBER ENGINE Deep Track AI.

Guards the investigation engine against out-of-scope prompts, general trivia,
creative writing, casual chat, or irrelevant queries. Ensures the AI remains strictly
dedicated to enterprise microservice telemetry, distributed trace correlation,
and threat analysis.
"""

import re
from typing import Tuple

OUT_OF_SCOPE_PATTERNS = [
    r"\b(capital of|population of|president of|prime minister of|who is|who was|when was|where is|how tall is)\b",
    r"\b(tell me a joke|tell a joke|write a joke|say a joke)\b",
    r"\b(write a poem|write a song|write a story|write an essay|write me a poem)\b",
    r"\b(recipe for|how to cook|how to bake|how to make|ingredients for)\b",
    r"\b(weather in|forecast for|temperature in)\b",
    r"\b(who won|score of|football match|cricket match|world cup|super bowl)\b",
    r"\b(calculate|solve equation|what is \d+\s*[\+\-\*\/\^]\s*\d+)\b",
    r"^(hi|hello|hey|howdy|sup|good morning|good afternoon|good evening|how are you|who are you)[\?\.\!]?$",
    r"\b(favorite color|best movie|meaning of life|horoscope|zodiac)\b",
]

SECURITY_OBSERVABILITY_KEYWORDS = {
    "event", "events", "telemetry", "trace", "traces", "microservice", "service", "services",
    "database", "db", "sql", "postgres", "redis", "kafka", "query", "queries", "pipeline",
    "ingest", "ingestion", "endpoint", "api", "auth", "token", "key", "keys", "brute",
    "login", "session", "user", "actor", "attack", "exfil", "exfiltration", "breach",
    "vulnerability", "cve", "log", "logs", "latency", "anomaly", "anomalous", "alert",
    "alerts", "detector", "detectors", "rule", "rules", "finding", "findings", "status",
    "receiving", "offline", "active", "health", "traffic", "packet", "network", "ip",
    "host", "port", "payload", "error", "errors", "500", "404", "401", "403", "exception",
    "worker", "rate", "slow", "flood", "ddos", "connection", "cluster", "container", "pod",
    "process", "incident", "investigation", "threat", "mitigation", "harvesting", "injection",
    "unauthorized", "credential", "password", "audit", "policy", "defense", "compromise",
    "why", "idle", "dropped", "drop", "failure", "fail", "slowdown", "memory", "cpu", "disk"
}


def is_query_in_scope(query: str) -> Tuple[bool, str]:
    """
    Evaluates whether a natural language query is relevant to cybersecurity telemetry,
    system observability, or incident response.

    Returns:
        (is_in_scope, rejection_reason)
    """
    cleaned = query.strip().lower()
    if len(cleaned) < 4:
        return False, "Query is too short or ambiguous to evaluate."

    for pat in OUT_OF_SCOPE_PATTERNS:
        if re.search(pat, cleaned):
            return False, "Query involves general trivia, entertainment, or non-technical topics."

    words = set(re.findall(r"[a-z0-9_-]+", cleaned))
    if not (words & SECURITY_OBSERVABILITY_KEYWORDS):
        return False, "Query lacks cybersecurity, microservice telemetry, or system observability concepts."

    return True, ""

