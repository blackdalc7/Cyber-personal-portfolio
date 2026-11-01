"""Who decides the next tool call: Claude (Anthropic API), a local model (Ollama), or the offline rules.

All three use the same :class:`~ai_analyst.engine.ToolSession`, so budgets, validation, untrusted-data wrapping and
citation checks apply equally. The offline provider needs no network or key; it is what CI, the eval gate and the
committed example transcripts use.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from .config import Settings
from .engine import SUBMIT, ProviderError, ToolSession

FALLBACK_BETA = "server-side-fallback-2026-07-01"


def _input(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return value
    return value


class AnthropicProvider:
    """Claude through the Messages API with a manual tool loop.

    Adaptive thinking and an explicit effort level; server-side fallbacks (``fallbacks="default"``) so a refusal by a
    safety classifier is retried on a substitute model instead of failing the investigation. Refusals that remain
    are reported, never parsed as an answer. The assistant content is appended back unchanged every turn.
    """

    name = "anthropic"

    def __init__(self, model: str, effort: str = "high", api_key: str = "", client: Any = None,
                 max_turns: int = 24, timeout_s: float = 300) -> None:
        if client is None:
            import anthropic

            client = anthropic.Anthropic(api_key=api_key or None, timeout=timeout_s)
        self.client = client
        self.model = model
        self.effort = effort
        self.max_turns = max_turns

    def run(self, session: ToolSession, system: str, task: str, incident_id: str) -> None:
        tools = [{"name": t["name"], "description": t["description"], "input_schema": t["input_schema"]}
                 for t in session.tool_specs()]
        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        nudged = False
        for _ in range(self.max_turns):
            resp = self.client.beta.messages.create(
                model=self.model, max_tokens=16000, system=system, tools=tools, messages=messages,
                thinking={"type": "adaptive"}, output_config={"effort": self.effort},
                betas=[FALLBACK_BETA], fallbacks="default")
            session.usage["turns"] += 1
            usage = getattr(resp, "usage", None)
            session.usage["input_tokens"] += int(getattr(usage, "input_tokens", 0) or 0)
            session.usage["output_tokens"] += int(getattr(usage, "output_tokens", 0) or 0)
            session.usage["served_model"] = getattr(resp, "model", None) or self.model
            if resp.stop_reason == "refusal":
                details = getattr(resp, "stop_details", None)
                raise ProviderError(f"model declined the request ({getattr(details, 'category', None) or 'refusal'})")
            if resp.stop_reason == "max_tokens":
                raise ProviderError("response hit max_tokens")
            messages.append({"role": "assistant", "content": resp.content})
            if resp.stop_reason == "pause_turn":
                continue
            uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]
            if not uses:
                if nudged:
                    raise ProviderError(f"model stopped without calling {SUBMIT}")
                nudged = True
                messages.append({"role": "user", "content": f"Call {SUBMIT} now with your verdict and evidence."})
                continue
            results = []
            for block in uses:  # every result goes back in one user message
                if block.name == SUBMIT:
                    ok, text = session.submit(_input(block.input))
                    results.append({"type": "tool_result", "tool_use_id": block.id, "content": text,
                                    "is_error": not ok})
                else:
                    _, text, is_error = session.call(block.name, _input(block.input))
                    results.append({"type": "tool_result", "tool_use_id": block.id, "content": text,
                                    "is_error": is_error})
            messages.append({"role": "user", "content": results})
            if session.final is not None:
                return
        raise ProviderError(f"no valid {SUBMIT} after {self.max_turns} turns")


class OllamaProvider:
    """A local model through Ollama's /api/chat with tools. Nothing leaves the machine."""

    name = "ollama"

    def __init__(self, url: str, model: str, client: httpx.Client | None = None, max_turns: int = 24,
                 timeout_s: float = 300) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.http = client or httpx.Client(timeout=timeout_s)
        self.max_turns = max_turns

    def run(self, session: ToolSession, system: str, task: str, incident_id: str) -> None:
        tools = [{"type": "function", "function": {"name": t["name"], "description": t["description"],
                                                   "parameters": t["input_schema"]}} for t in session.tool_specs()]
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}, {"role": "user", "content": task}]
        nudged = False
        for _ in range(self.max_turns):
            try:
                r = self.http.post(f"{self.url}/api/chat", json={
                    "model": self.model, "messages": messages, "tools": tools, "stream": False,
                    "options": {"temperature": 0}})
                r.raise_for_status()
                data = r.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise ProviderError(f"Ollama request failed: {exc.__class__.__name__}") from exc
            session.usage["turns"] += 1
            session.usage["input_tokens"] += int(data.get("prompt_eval_count") or 0)
            session.usage["output_tokens"] += int(data.get("eval_count") or 0)
            msg = data.get("message") or {}
            messages.append({k: v for k, v in msg.items() if k in ("role", "content", "tool_calls")})
            calls = msg.get("tool_calls") or []
            if not calls:
                if nudged:
                    raise ProviderError(f"model stopped without calling {SUBMIT}")
                nudged = True
                messages.append({"role": "user", "content": f"Call {SUBMIT} now with your verdict and evidence."})
                continue
            for c in calls:
                fn = c.get("function") or {}
                name, args = str(fn.get("name", "")), _input(fn.get("arguments"))
                if name == SUBMIT:
                    _, text = session.submit(args)
                else:
                    _, text, _ = session.call(name, args)
                messages.append({"role": "tool", "tool_name": name, "content": text})
            if session.final is not None:
                return
        raise ProviderError(f"no valid {SUBMIT} after {self.max_turns} turns")


def make_provider(settings: Settings) -> Any:
    if settings.provider == "anthropic":
        return AnthropicProvider(settings.model, settings.effort, settings.anthropic_api_key,
                                 timeout_s=settings.timeout_s)
    if settings.provider == "ollama":
        return OllamaProvider(settings.ollama_url, settings.ollama_model, timeout_s=settings.timeout_s)
    from .offline import OfflineProvider

    return OfflineProvider()
