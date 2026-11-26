"""Model access and its guardrails - spec §8.3."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import anthropic
import httpx
import pytest
from pydantic import BaseModel

from aegis.ai.client import (
    AnthropicLlmClient,
    LlmError,
    LlmRefusal,
    LlmUnavailable,
    build_client,
)
from aegis.ai.privacy import PrivacyGuard, PrivacyViolation, PublicPayload, TenantIdentifiers
from aegis.config import Settings


class Reply(BaseModel):
    verdict: str


def _payload(text: str = "CVE-2024-21762 affects FortiOS.") -> PublicPayload:
    return PublicPayload(kind="intel_record", text=text)


def _settings(**overrides: Any) -> Settings:
    fields: dict[str, Any] = {
        "llm_api_key": "test-key",
        "llm_model": "claude-opus-5-5",
        "llm_max_tokens": 1000,
    }
    fields.update(overrides)
    return Settings(**fields)


class FakeMessages:
    """Stands in for ``client.messages``; records the request."""

    def __init__(self, response: Any) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response

    def parse(self, **kwargs: Any) -> Any:
        return self.create(**kwargs)


def _sdk(response: Any) -> Any:
    return SimpleNamespace(messages=FakeMessages(response))


def _text_response(text: str, **extra: Any) -> Any:
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)],
        stop_reason=extra.pop("stop_reason", "end_turn"),
        stop_details=extra.pop("stop_details", None),
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
        **extra,
    )


class TestBuildClient:
    def test_a_disabled_llm_is_refused(self) -> None:
        with pytest.raises(LlmUnavailable, match="disabled"):
            build_client(settings=Settings(llm_enabled=False))

    def test_self_hosted_needs_a_base_url(self) -> None:
        with pytest.raises(LlmUnavailable, match="llm_base_url"):
            build_client(settings=Settings(llm_provider="self_hosted"))

    def test_zero_retention_requires_an_explicit_key(self) -> None:
        """Spec §8.3: ambient credentials may belong to a retaining account."""
        with pytest.raises(LlmUnavailable, match="zero retention"):
            build_client(
                settings=Settings(
                    llm_require_zero_retention=True,
                    llm_provider="anthropic",
                    llm_api_key=None,
                )
            )

    def test_an_explicit_key_satisfies_it(self) -> None:
        client = build_client(settings=_settings())
        assert isinstance(client, AnthropicLlmClient)

    def test_a_self_hosted_endpoint_satisfies_it(self) -> None:
        """The other deployment §8.3 allows."""
        client = build_client(
            settings=Settings(
                llm_provider="self_hosted",
                llm_base_url="http://vllm.internal.test:8000",
                llm_api_key="unused",
            )
        )
        assert isinstance(client, AnthropicLlmClient)


class TestPrivacyEnforcement:
    def test_a_payload_with_tenant_data_never_reaches_the_sdk(self) -> None:
        """The guard runs before the request, not after."""
        sdk = _sdk(_text_response("should not get here"))
        client = AnthropicLlmClient(
            settings=_settings(),
            guard=PrivacyGuard(TenantIdentifiers(hostnames=frozenset({"vpn.acme.example.com"}))),
            client=sdk,
        )

        with pytest.raises(PrivacyViolation):
            client.draft(
                system="s",
                payload=_payload("Patch vpn.acme.example.com now"),
                instructions="i",
            )
        assert sdk.messages.calls == []


class TestDraft:
    def test_returns_the_text_blocks(self) -> None:
        client = AnthropicLlmClient(
            settings=_settings(), client=_sdk(_text_response("  Upgrade to 7.4.3.  "))
        )
        assert client.draft(system="s", payload=_payload(), instructions="i") == (
            "Upgrade to 7.4.3."
        )

    def test_sends_the_configured_model_and_effort(self) -> None:
        sdk = _sdk(_text_response("x"))
        client = AnthropicLlmClient(settings=_settings(llm_effort="low"), client=sdk)
        client.draft(system="s", payload=_payload(), instructions="i")

        request = sdk.messages.calls[0]
        assert request["model"] == "claude-opus-5-5"
        assert request["output_config"] == {"effort": "low"}
        assert request["system"] == "s"

    def test_a_refusal_is_reported_as_such(self) -> None:
        response = _text_response(
            "",
            stop_reason="refusal",
            stop_details=SimpleNamespace(category="cyber", explanation="no"),
        )
        client = AnthropicLlmClient(settings=_settings(), client=_sdk(response))

        with pytest.raises(LlmRefusal, match="cyber"):
            client.draft(system="s", payload=_payload(), instructions="i")


class TestExtract:
    def test_returns_the_parsed_output(self) -> None:
        response = _text_response("", parsed_output=Reply(verdict="exploited"))
        client = AnthropicLlmClient(settings=_settings(), client=_sdk(response))

        result = client.extract(system="s", payload=_payload(), schema=Reply, instructions="i")
        assert result.verdict == "exploited"

    def test_page_text_is_wrapped_as_untrusted(self) -> None:
        """Spec §8.3: fetched content is data, not instructions."""
        sdk = _sdk(_text_response("", parsed_output=Reply(verdict="x")))
        client = AnthropicLlmClient(settings=_settings(), client=sdk)
        client.extract(
            system="s",
            payload=PublicPayload(kind="advisory_page", text="page body"),
            schema=Reply,
            instructions="i",
        )

        sent = sdk.messages.calls[0]["messages"][0]["content"]
        assert "UNTRUSTED_PAGE_CONTENT" in sent
        assert "page body" in sent

    def test_missing_structured_output_is_an_error(self) -> None:
        response = _text_response("", parsed_output=None)
        client = AnthropicLlmClient(settings=_settings(), client=_sdk(response))

        with pytest.raises(LlmError, match="no structured output"):
            client.extract(system="s", payload=_payload(), schema=Reply, instructions="i")


class TestErrorMapping:
    def test_a_connection_failure_is_unavailable(self) -> None:
        error = anthropic.APIConnectionError(request=httpx.Request("POST", "https://x"))
        client = AnthropicLlmClient(settings=_settings(), client=_sdk(error))

        with pytest.raises(LlmUnavailable, match="cannot reach"):
            client.draft(system="s", payload=_payload(), instructions="i")

    def test_a_rate_limit_is_an_error_not_a_crash(self) -> None:
        error = anthropic.RateLimitError(
            "slow down",
            response=httpx.Response(429, request=httpx.Request("POST", "https://x")),
            body=None,
        )
        client = AnthropicLlmClient(settings=_settings(), client=_sdk(error))

        with pytest.raises(LlmError, match="rate limited"):
            client.draft(system="s", payload=_payload(), instructions="i")

    def test_a_status_error_reports_the_code(self) -> None:
        error = anthropic.APIStatusError(
            "bad request",
            response=httpx.Response(400, request=httpx.Request("POST", "https://x")),
            body=None,
        )
        client = AnthropicLlmClient(settings=_settings(), client=_sdk(error))

        with pytest.raises(LlmError, match="400"):
            client.draft(system="s", payload=_payload(), instructions="i")
