"""
Pretrained Model API Provider for CrimeLens.

Provides a clean abstraction to call any pretrained language model
via an OpenAI-compatible API (OpenAI, Groq, Ollama, OpenRouter, vLLM, DeepSeek, etc.).
Includes robust timeout and error handling without credential leakage.
"""

import os
from typing import List, Dict, Any, Optional
from ..config import OPENAI_API_KEY, OPENAI_MODEL, OPENAI_BASE_URL


def is_model_api_configured() -> bool:
    """Check whether a pretrained model API key is configured."""
    return bool(OPENAI_API_KEY and OPENAI_API_KEY.strip())


def get_model_info() -> Dict[str, Any]:
    """Return model provider metadata without revealing secrets."""
    configured = is_model_api_configured()
    base_url = OPENAI_BASE_URL if OPENAI_BASE_URL else "https://api.openai.com/v1"
    return {
        "configured": configured,
        "model": OPENAI_MODEL,
        "base_url": base_url,
        "provider": "OpenAI-Compatible API" if configured else "Local Synthesis Fallback",
    }


def call_pretrained_model(
    messages: List[Dict[str, str]],
    temperature: float = 0.1,
    max_tokens: int = 1000,
    timeout: float = 15.0,
) -> Dict[str, Any]:
    """
    Call the configured pretrained model API.

    Returns:
        {
            "ok": bool,
            "content": Optional[str],
            "error": Optional[str],
            "model": str,
        }
    """
    if not is_model_api_configured():
        return {
            "ok": False,
            "content": None,
            "error": "MODEL_API_NOT_CONFIGURED",
            "model": OPENAI_MODEL,
        }

    try:
        from openai import OpenAI

        kwargs: Dict[str, Any] = {
            "api_key": OPENAI_API_KEY.strip(),
            "timeout": timeout,
        }
        if OPENAI_BASE_URL and OPENAI_BASE_URL.strip():
            kwargs["base_url"] = OPENAI_BASE_URL.strip()

        client = OpenAI(**kwargs)

        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        content = ""
        if response.choices and len(response.choices) > 0:
            content = response.choices[0].message.content or ""

        if not content.strip():
            return {
                "ok": False,
                "content": None,
                "error": "EMPTY_MODEL_RESPONSE",
                "model": OPENAI_MODEL,
            }

        return {
            "ok": True,
            "content": content.strip(),
            "error": None,
            "model": OPENAI_MODEL,
        }

    except Exception as exc:
        # Sanitize error to avoid leaking API keys or credentials
        error_name = type(exc).__name__
        return {
            "ok": False,
            "content": None,
            "error": error_name,
            "model": OPENAI_MODEL,
        }
