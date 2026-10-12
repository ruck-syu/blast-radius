"""Optional LLM explanation layer.

The agent works fully without an LLM (deterministic plan + template
explanations). When an API key is configured, `summarize` asks the model for
the final triage summary; any failure falls back to the template (returns None).

Config via environment (never hard-code secrets):
  LLM_PROVIDER=anthropic|openai   (auto-detected from keys when unset)
  LLM_MODEL=...                   (sensible default per provider)
  ANTHROPIC_API_KEY / OPENAI_API_KEY
"""
from __future__ import annotations

import logging
import os

log = logging.getLogger("blast-radius.agent")


def summarize(prompt: str, timeout_s: int = 30) -> str | None:
    provider = os.getenv("LLM_PROVIDER", "").lower()
    if not provider:
        if os.getenv("ANTHROPIC_API_KEY"):
            provider = "anthropic"
        elif os.getenv("OPENAI_API_KEY"):
            provider = "openai"
        else:
            return None
    try:
        if provider == "anthropic":
            return _anthropic(prompt, timeout_s)
        if provider == "openai":
            return _openai(prompt, timeout_s)
        log.warning("unknown LLM_PROVIDER=%r, using template", provider)
        return None
    except Exception as e:  # never break triage on LLM failure
        log.warning("LLM summarization failed (%s), using template", e)
        return None


def _anthropic(prompt: str, timeout_s: int) -> str:
    import anthropic  # lazy: optional dependency

    client = anthropic.Anthropic(timeout=timeout_s)
    msg = client.messages.create(
        model=os.getenv("LLM_MODEL", "claude-sonnet-4-20250514"),
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(b.text for b in msg.content if b.type == "text").strip()


def _openai(prompt: str, timeout_s: int) -> str:
    import openai  # lazy: optional dependency

    client = openai.OpenAI(timeout=timeout_s)
    resp = client.chat.completions.create(
        model=os.getenv("LLM_MODEL", "gpt-4o-mini"),
        max_tokens=300,
        messages=[{"role": "user", "content": prompt}],
    )
    return (resp.choices[0].message.content or "").strip()
