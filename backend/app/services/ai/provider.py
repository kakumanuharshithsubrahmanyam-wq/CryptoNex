"""Optional OpenAI-compatible chat provider. Missing credentials disable AI only."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request

from app.core.config import Settings

logger = logging.getLogger(__name__)

SYSTEM_INSTRUCTION = (
    "You are CryptoNex AI Crypto Architect.\n"
    "Only use facts contained in the supplied CryptoNex scan data.\n"
    "Do not invent algorithms, dependencies, files, vulnerabilities, or evidence.\n"
    "Distinguish observed facts from recommendations.\n"
    "If information is missing, say that it is unknown.\n"
    "Do not claim the application is quantum-safe.\n"
    "Do not claim a migration occurred unless the supplied data proves it.\n"
    "When recommending migration candidates, explain the cryptographic role and trade-offs."
)


class AIProvider:
    def __init__(self, settings: Settings) -> None:
        self.api_key = (settings.openai_api_key or "").strip()
        self.model = (settings.openai_model or "gpt-4o-mini").strip() or "gpt-4o-mini"
        self.base_url = (settings.openai_base_url or "https://api.openai.com/v1").rstrip("/")
        timeout = getattr(settings, "openai_timeout_seconds", 30)
        self.timeout_seconds = timeout if isinstance(timeout, int) and timeout > 0 else 30

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def complete(self, messages: list[dict]) -> str:
        if not self.available:
            raise RuntimeError("AI provider is unavailable")
        payload = json.dumps(
            {"model": self.model, "messages": messages, "temperature": 0}
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("AI provider request failed type=%s", type(exc).__name__)
            raise RuntimeError("AI provider request failed") from exc
        choices = body.get("choices") if isinstance(body, dict) else None
        if not choices:
            raise RuntimeError("AI provider returned no choices")
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str) or not content.strip():
            raise RuntimeError("AI provider returned an empty message")
        return content.strip()


def provider_from_settings(settings: Settings) -> AIProvider:
    return AIProvider(settings)
