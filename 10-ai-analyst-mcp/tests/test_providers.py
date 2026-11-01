from __future__ import annotations

import json
from types import SimpleNamespace as NS

import httpx
import pytest
from conftest import MALDOC

from ai_analyst.config import Settings
from ai_analyst.engine import SUBMIT, ProviderError, investigate
from ai_analyst.offline import OfflineProvider
from ai_analyst.providers import FALLBACK_BETA, AnthropicProvider, OllamaProvider, make_provider

GOOD = {"verdict": "true_positive", "confidence": 0.88, "summary": "Word spawned encoded PowerShell on ws01.",
        "evidence": [{"tool_call": "c1", "quote": "Canary file tampered"}], "recommended_actions": []}


def tool_use(i: int, name: str, inp) -> NS:
    return NS(type="tool_use", id=f"tu{i}", name=name, input=inp)


def response(stop: str, *content, category=None) -> NS:
    return NS(stop_reason=stop, content=list(content), model="claude-opus-5-5",
              usage=NS(input_tokens=100, output_tokens=20), stop_details=NS(category=category) if category else None)


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.beta = NS(messages=NS(create=self.create))

    def create(self, **kw):
        self.calls.append({**kw, "messages": list(kw["messages"])})
        return self.responses.pop(0)


def test_anthropic_loop(box, server) -> None:
    client = FakeClient([
        response("tool_use", NS(type="thinking", thinking=""),
                 tool_use(1, "get_incident", {"incident_id": MALDOC}), tool_use(2, "isolate_host", {"h": "ws01"})),
        response("pause_turn", NS(type="text", text="...")),
        response("end_turn", NS(type="text", text="Done.")),
        response("tool_use", tool_use(3, SUBMIT, json.dumps(GOOD))),
    ])
    doc = investigate(MALDOC, box, server, AnthropicProvider("claude-opus-5-5", "high", client=client))
    first = client.calls[0]
    assert first["model"] == "claude-opus-5-5" and first["thinking"] == {"type": "adaptive"}
    assert first["output_config"] == {"effort": "high"} and first["betas"] == [FALLBACK_BETA]
    assert first["fallbacks"] == "default" and first["max_tokens"] == 16000
    assert {t["name"] for t in first["tools"]} >= {"get_incident", SUBMIT}
    results = client.calls[1]["messages"][-1]["content"]
    assert [r["tool_use_id"] for r in results] == ["tu1", "tu2"]  # all results in one user message
    assert results[0]["is_error"] is False and results[1]["is_error"] is True
    assert "untrusted_data" in results[0]["content"]
    assert client.calls[1]["messages"][-2]["content"][0].type == "thinking"  # content passed back unchanged
    assert client.calls[3]["messages"][-1]["content"].startswith(f"Call {SUBMIT}")
    assert doc["verdict"] == "true_positive" and doc["usage"]["turns"] == 4 and doc["usage"]["input_tokens"] == 400
    assert doc["model"] == "claude-opus-5-5" and doc["refused_calls"][0]["tool"] == "isolate_host"


@pytest.mark.parametrize(("responses", "match"), [
    ([response("refusal", category="cyber")], "declined.*cyber"),
    ([response("max_tokens")], "max_tokens"),
    ([response("end_turn"), response("end_turn")], "without calling"),
])
def test_anthropic_failures(box, server, responses, match) -> None:
    with pytest.raises(ProviderError, match=match):
        investigate(MALDOC, box, server, AnthropicProvider("m", client=FakeClient(responses)))


def test_anthropic_turn_limit(box, server) -> None:
    client = FakeClient([response("tool_use", tool_use(i, "list_incidents", {})) for i in range(3)])
    with pytest.raises(ProviderError, match="after 3 turns"):
        investigate(MALDOC, box, server, AnthropicProvider("m", client=client, max_turns=3))


def ollama(handler) -> OllamaProvider:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return OllamaProvider("http://ollama:11434/", "qwen3:32b", client=http)


def test_ollama_loop(box, server) -> None:
    replies = [
        {"message": {"role": "assistant", "content": "",
                     "tool_calls": [{"function": {"name": "get_incident", "arguments": {"incident_id": MALDOC}}}]},
         "prompt_eval_count": 50, "eval_count": 5},
        {"message": {"role": "assistant", "content": "thinking"}},
        {"message": {"role": "assistant", "content": "",
                     "tool_calls": [{"function": {"name": SUBMIT, "arguments": json.dumps(GOOD)}}]}},
    ]
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        body = json.loads(req.content)
        seen.append(body)
        assert req.url == "http://ollama:11434/api/chat" and body["stream"] is False
        return httpx.Response(200, json=replies[len(seen) - 1])

    doc = investigate(MALDOC, box, server, ollama(handler))
    assert seen[0]["tools"][0]["type"] == "function" and seen[0]["messages"][0]["role"] == "system"
    assert seen[1]["messages"][-1]["role"] == "tool" and "untrusted_data" in seen[1]["messages"][-1]["content"]
    assert doc["provider"] == "ollama" and doc["model"] == "qwen3:32b" and doc["usage"]["input_tokens"] == 50


def test_ollama_errors(box, server) -> None:
    with pytest.raises(ProviderError, match="Ollama request failed"):
        investigate(MALDOC, box, server, ollama(lambda r: httpx.Response(500)))
    quiet = {"message": {"role": "assistant", "content": "no tools"}}
    with pytest.raises(ProviderError, match="without calling"):
        investigate(MALDOC, box, server, ollama(lambda r: httpx.Response(200, json=quiet)))


def test_make_provider() -> None:
    s = Settings.from_env({}, dotenv=False)
    assert isinstance(make_provider(s), OfflineProvider)
    assert isinstance(make_provider(Settings.from_env({"ANALYST_PROVIDER": "ollama"}, dotenv=False)), OllamaProvider)
    p = make_provider(Settings.from_env({"ANALYST_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": "sk-test"},
                                        dotenv=False))
    assert isinstance(p, AnthropicProvider) and p.model == "claude-opus-5-5"
