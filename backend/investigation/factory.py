"""
Factory for creating the configured BaseInvestigator.
"""

from typing import Optional
from backend.config import settings
from backend.investigation.adapters import (
    BaseInvestigator,
    MockInvestigator,
    MetaModelInvestigator,
    OpenAICompatibleInvestigator,
    MuseInvestigator,
)


def get_investigator(provider_override: Optional[str] = None) -> BaseInvestigator:
    """
    Returns the configured BaseInvestigator instance.
    Supports runtime override or fallback to application settings.
    """
    provider = (provider_override or settings.INVESTIGATOR_PROVIDER).lower().strip()

    if provider == "muse":
        return MuseInvestigator(
            api_key=settings.INVESTIGATOR_API_KEY,
            base_url=settings.INVESTIGATOR_BASE_URL,
            model=settings.INVESTIGATOR_MODEL,
            timeout=settings.INVESTIGATOR_TIMEOUT_SECONDS,
        )
    elif provider == "meta":
        return MetaModelInvestigator(
            api_key=settings.INVESTIGATOR_API_KEY,
            base_url=settings.INVESTIGATOR_BASE_URL,
            model=settings.INVESTIGATOR_MODEL,
            timeout=settings.INVESTIGATOR_TIMEOUT_SECONDS,
        )
    elif provider in ("openai", "openai_compatible", "ollama", "vllm", "groq", "together"):
        return OpenAICompatibleInvestigator(
            api_key=settings.INVESTIGATOR_API_KEY,
            base_url=settings.INVESTIGATOR_BASE_URL,
            model=settings.INVESTIGATOR_MODEL,
            timeout=settings.INVESTIGATOR_TIMEOUT_SECONDS,
        )

    elif provider == "mock":
        return MockInvestigator()

    # Default to Muse AI provider
    return MuseInvestigator(
        api_key=settings.INVESTIGATOR_API_KEY,
        base_url=settings.INVESTIGATOR_BASE_URL,
        model=settings.INVESTIGATOR_MODEL,
        timeout=settings.INVESTIGATOR_TIMEOUT_SECONDS,
    )

