"""
Workspace Assistant API - Cybersecurity-only conversational AI.
Strictly restricted to cybersecurity topics. Refuses off-topic queries.
"""

import logging
import uuid
from typing import Optional, List
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.config import settings
from backend.core.auth import AuthContext, require_permission, Permission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/assistant", tags=["assistant"])

# In-memory conversation store: { conversation_id: [ {"role": ..., "content": ...} ] }
# Bounded per conversation (max 20 turns), auto-expires old conversations
_conversations: dict[str, list] = defaultdict(list)
_conversation_timestamps: dict[str, datetime] = {}
_MAX_TURNS = 20
_CONVERSATION_TTL_HOURS = 2


def _prune_old_conversations():
    """Remove conversations older than TTL."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=_CONVERSATION_TTL_HOURS)
    stale = [cid for cid, ts in _conversation_timestamps.items() if ts < cutoff]
    for cid in stale:
        _conversations.pop(cid, None)
        _conversation_timestamps.pop(cid, None)


SYSTEM_PROMPT = """You are the Ternline Workspace Security Assistant — an enterprise-grade AI assistant embedded in the Ternline CYBER ENGINE Security Intelligence Platform.

STRICT DOMAIN ENFORCEMENT:
You are EXCLUSIVELY a cybersecurity assistant. You ONLY answer questions about:
- Cybersecurity threats, vulnerabilities, attack techniques (MITRE ATT&CK, CVEs)
- Incident response, threat hunting, forensic analysis
- Security operations (SOC, SIEM, SOAR workflows)
- Network security, endpoint security, cloud security
- Authentication, authorization, identity security (MFA, OAuth, JWT, API keys)
- Cryptography and PKI
- Detection engineering, rule writing (YARA, Sigma, Snort/Suricata)
- Threat intelligence, IOC analysis, threat feeds
- Vulnerability management and penetration testing concepts
- Compliance frameworks: SOC2, ISO 27001, NIST CSF, PCI-DSS, HIPAA
- The Ternline platform itself: Fast Track detection, Deep Track investigations, findings, rules, events, telemetry, API keys, workspaces, defense policies
- Security best practices for microservices, APIs, databases, cloud infrastructure
- Malware analysis, reverse engineering concepts
- Zero-trust architecture, security architecture review

REFUSAL RULE — NON-NEGOTIABLE:
If a user asks about ANYTHING not directly related to cybersecurity or the Ternline platform, you MUST respond with:
"I'm strictly a cybersecurity assistant for the Ternline platform. I can only help with security operations, threat detection, incident response, and related cybersecurity topics. For general questions, please use a general-purpose assistant."

Do NOT answer questions about:
- Food, recipes, nutrition, health (unless it's about operational security hygiene)
- Sports, entertainment, pop culture
- Mathematics, physics, chemistry unrelated to cryptography
- Travel, geography, history (unless cyber-history like notable breaches)
- General coding questions unrelated to security
- Personal advice, relationships
- Politics, religion, philosophy

RESPONSE STYLE:
- Be concise, precise, and actionable.
- Use technical security terminology appropriately.
- When discussing Ternline-specific features, reference Fast Track (deterministic detection engine), Deep Track (AI investigation), findings, rules, events, telemetry ingestion.
- Format responses with markdown when helpful (code blocks for rule examples, bullet points for steps).
- Always ground recommendations in the evidence or context provided.
- Never hallucinate CVE numbers, event IDs, or specific findings not mentioned by the user.
"""


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    conversation_id: Optional[str] = None
    context: Optional[dict] = None


class ChatResponse(BaseModel):
    reply: str
    conversation_id: str


async def _call_llm(messages: list, tenant_id: str) -> str:
    """Call the configured LLM provider for the assistant."""

    provider = settings.INVESTIGATOR_PROVIDER
    if provider == "mock":
        user_msg = messages[-1]["content"] if messages else ""
        off_topic_keywords = [
            "banana", "fruit", "recipe", "cook", "sport", "football",
            "weather", "movie", "joke", "song", "diet"
        ]
        if any(w in user_msg.lower() for w in off_topic_keywords):
            return (
                "I'm strictly a cybersecurity assistant for the Ternline platform. "
                "I can only help with security operations, threat detection, incident response, "
                "and related cybersecurity topics. For general questions, please use a general-purpose assistant."
            )
        return (
            "I am the Ternline Workspace Security Assistant. "
            "Fast Track detection and telemetry processing are operating within normal baseline parameters. "
            "How can I assist with your security operations?"
        )

    base_url = settings.INVESTIGATOR_BASE_URL.rstrip("/")
    api_key = settings.INVESTIGATOR_API_KEY
    model = settings.INVESTIGATOR_MODEL
    timeout = min(settings.INVESTIGATOR_TIMEOUT_SECONDS, 45.0)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 1024,
    }

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                f"{base_url}/chat/completions",
                headers=headers,
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            return content.strip()
    except httpx.HTTPStatusError as e:
        code = e.response.status_code
        if code == 401:
            logger.error("Assistant LLM: Authentication failed (401). Check INVESTIGATOR_API_KEY.")
            raise HTTPException(
                status_code=503,
                detail="Assistant AI service authentication failed. Contact your administrator.",
            )
        elif code == 429:
            logger.error("Assistant LLM: Rate limit exceeded (429).")
            raise HTTPException(
                status_code=503,
                detail="Assistant AI service is temporarily rate-limited. Please try again shortly.",
            )
        else:
            logger.error("Assistant LLM: HTTP error %s — %s", code, e.response.text[:200])
            raise HTTPException(
                status_code=503,
                detail=f"Assistant AI service error (HTTP {code}). Try again later.",
            )
    except httpx.TimeoutException:
        logger.error("Assistant LLM: Request timed out after %ss.", timeout)
        raise HTTPException(
            status_code=504,
            detail="Assistant AI service timed out. Try a shorter query.",
        )
    except Exception as e:
        logger.error("Assistant LLM: Unexpected error — %s", e)
        raise HTTPException(status_code=503, detail="Assistant AI service unavailable.")


@router.post("/chat", response_model=ChatResponse)
async def assistant_chat(
    req: ChatRequest,
    auth: AuthContext = Depends(require_permission(Permission.FINDINGS_READ)),
):
    """
    Cybersecurity-only workspace assistant chat endpoint.
    Strictly restricted to cybersecurity and Ternline platform topics.
    """
    _prune_old_conversations()

    # Get or create conversation
    conversation_id = req.conversation_id or str(uuid.uuid4())
    history = _conversations[conversation_id]

    # Build page context hint for the system
    page_context = ""
    if req.context and req.context.get("current_page"):
        page_map = {
            "overview": "The user is on the Overview/Dashboard page showing security metrics.",
            "findings": "The user is on the Security Findings page showing threat detections.",
            "events": "The user is on the Event Explorer page showing telemetry events.",
            "investigations": "The user is on the Deep Investigation page.",
            "rules": "The user is on the Rule Registry page managing detection rules.",
            "defense": "The user is on the Active Defense page.",
            "health": "The user is on the Ingestion & Health page.",
            "incidents": "The user is on the Finding Clusters page.",
            "hunting": "The user is on the Threat Hunting workspace.",
            "threatIntel": "The user is on the IOC Telemetry Search page.",
            "coverage": "The user is on the Detection Coverage page.",
            "assets": "The user is on the API Credentials page.",
            "audit": "The user is on the Audit & Evidence page.",
            "governance": "The user is on the AI Governance page.",
            "settings": "The user is on the Platform & Workspace Settings page.",
        }
        page_hint = page_map.get(req.context["current_page"], "")
        if page_hint:
            page_context = f"\n\nCurrent Console Context: {page_hint}"

    # Build messages list
    system_content = SYSTEM_PROMPT
    if page_context:
        system_content += page_context

    messages = [{"role": "system", "content": system_content}]

    # Add capped history (last _MAX_TURNS turns = _MAX_TURNS * 2 messages)
    messages.extend(history[-(_MAX_TURNS * 2):])

    # Add current user message
    messages.append({"role": "user", "content": req.message})

    # Call LLM
    reply = await _call_llm(messages, tenant_id=auth.tenant_id)

    # Update conversation history
    history.append({"role": "user", "content": req.message})
    history.append({"role": "assistant", "content": reply})

    # Keep history bounded
    if len(history) > _MAX_TURNS * 2:
        _conversations[conversation_id] = history[-(_MAX_TURNS * 2):]

    _conversation_timestamps[conversation_id] = datetime.now(timezone.utc)

    logger.info(
        "Assistant chat: tenant=%s, conv=%s, msg_len=%d, reply_len=%d",
        auth.tenant_id,
        conversation_id[:8],
        len(req.message),
        len(reply),
    )

    return ChatResponse(reply=reply, conversation_id=conversation_id)


@router.delete("/chat/{conversation_id}", status_code=204)
async def clear_conversation(
    conversation_id: str,
    auth: AuthContext = Depends(require_permission(Permission.FINDINGS_READ)),
):
    """Clear a specific conversation's history."""
    _conversations.pop(conversation_id, None)
    _conversation_timestamps.pop(conversation_id, None)
