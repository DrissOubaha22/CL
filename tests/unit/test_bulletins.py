"""Bulletin drafting, routing and rendering - spec §8."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from aegis.ai.client import LlmError
from aegis.ai.privacy import PublicPayload
from aegis.bulletins.drafting import Draft, PublicIntelView, draft_public_prose
from aegis.bulletins.routing import RoutingInputs, route_bulletin
from aegis.bulletins.templates import TenantContext, render_bulletin
from aegis.core.enums import (
    AutomationPolicy,
    Criticality,
    ExploitStatus,
    ExposureClass,
    MatchFlag,
    ReviewReason,
    Tier,
)

NOW = datetime(2026, 11, 26, tzinfo=UTC)


def view(**overrides: Any) -> PublicIntelView:
    fields: dict[str, Any] = {
        "cve_id": "CVE-2024-21762",
        "exploit_status": ExploitStatus.ACTIVE,
        "on_kev": True,
        "vendor_confirmed": False,
        "ransomware": True,
        "patch_available": True,
        "config_dependent": False,
        "cvss": 9.8,
        "epss": 0.9412,
        "cwe": ("CWE-787",),
        "description": "A stack-based buffer overflow in the SSL VPN.",
        "affected_summary": ("fortinet fortios >= 7.4.0 < 7.4.3",),
    }
    fields.update(overrides)
    return PublicIntelView(**fields)


class RecordingLlm:
    """Captures exactly what the model was given."""

    def __init__(self, reply: str = "Upgrade to 7.4.3.") -> None:
        self.reply = reply
        self.payloads: list[str] = []

    def draft(self, *, system: str, payload: PublicPayload, instructions: str) -> str:
        self.payloads.append(payload.text)
        return self.reply

    def extract(self, **kwargs: Any) -> Any:  # pragma: no cover - unused here
        raise NotImplementedError


class FailingLlm(RecordingLlm):
    def draft(self, **kwargs: Any) -> str:
        raise LlmError("provider unavailable")


class TestPublicView:
    def test_the_payload_carries_only_public_facts(self) -> None:
        text = view().as_payload().text
        assert "CVE-2024-21762" in text
        assert "CVSS base score: 9.8" in text
        assert "On the CISA KEV catalogue: yes" in text
        assert "fortinet fortios" in text

    def test_the_view_is_built_only_from_an_intel_record(self) -> None:
        """Spec §8.1 holds because there is no other constructor."""
        from aegis.bulletins import drafting

        assert drafting.public_view_of.__annotations__["record"] == "IntelRecord"


class TestDrafting:
    def test_the_model_sees_the_public_payload(self) -> None:
        llm = RecordingLlm()
        draft = draft_public_prose(view(), llm=llm, model_name="claude-opus-5-5")

        assert draft.text == "Upgrade to 7.4.3."
        assert draft.is_model_written
        assert draft.model == "claude-opus-5-5"
        assert len(llm.payloads) == 1

    def test_the_model_flag_does_not_depend_on_the_name(self) -> None:
        """Regression: deriving it from `model` made an unnamed model draft
        look like a failed one, which blocked auto-issue under §8.2."""
        draft = draft_public_prose(view(), llm=RecordingLlm(), model_name=None)
        assert draft.is_model_written
        assert draft.model is None

    def test_no_model_falls_back_to_deterministic_prose(self) -> None:
        """A deployment with the LLM off still issues bulletins."""
        draft = draft_public_prose(view(), llm=None)

        assert not draft.is_model_written
        assert "stack-based buffer overflow" in draft.text
        assert "ransomware" in draft.text

    def test_a_model_failure_degrades_rather_than_raising(self) -> None:
        """A finding nobody is told about is worse than plainer prose."""
        draft = draft_public_prose(view(), llm=FailingLlm(), model_name="x")

        assert not draft.is_model_written
        assert draft.text

    def test_an_empty_reply_falls_back(self) -> None:
        draft = draft_public_prose(view(), llm=RecordingLlm("   "), model_name="x")
        assert not draft.is_model_written

    @pytest.mark.parametrize(
        ("status", "expected"),
        [
            (ExploitStatus.ACTIVE, "exploitation is confirmed"),
            (ExploitStatus.POC, "Public exploit code exists"),
            (ExploitStatus.NONE, "No exploitation has been confirmed"),
        ],
    )
    def test_the_fallback_states_the_exploitation_status(
        self, status: ExploitStatus, expected: str
    ) -> None:
        draft = draft_public_prose(view(exploit_status=status), llm=None)
        assert expected.lower() in draft.text.lower()

    def test_the_fallback_says_when_no_patch_exists(self) -> None:
        draft = draft_public_prose(view(patch_available=False), llm=None)
        assert "No vendor patch is recorded" in draft.text

    def test_the_fallback_flags_config_dependence(self) -> None:
        draft = draft_public_prose(view(config_dependent=True), llm=None)
        assert "configuration" in draft.text


class TestRouting:
    """Spec §8.2's three rows."""

    def _inputs(self, **overrides: Any) -> RoutingInputs:
        fields: dict[str, Any] = {
            "tier": Tier.HIGH,
            "exploit_status": ExploitStatus.ACTIVE,
            "vendor_confirmed": False,
            "patch_available": True,
            "exposure_verified": True,
            "criticality": Criticality.MEDIUM,
            "auto_escalatable": True,
            "automation_policy": AutomationPolicy.AUTO_ISSUE_VERIFIED,
        }
        fields.update(overrides)
        return RoutingInputs(**fields)

    def test_row_one_auto_issues(self) -> None:
        """Exploited + patch available + exposure verified."""
        decision = route_bulletin(self._inputs())
        assert decision.auto_issue
        assert decision.reasons == []

    @pytest.mark.parametrize(
        ("override", "reason"),
        [
            ({"patch_available": False}, ReviewReason.NO_PATCH),
            ({"exposure_verified": False}, ReviewReason.EXPOSURE_UNVERIFIED),
            ({"conflicting_intel": True}, ReviewReason.CONFLICTING_INTEL),
            ({"auto_escalatable": False}, ReviewReason.NOT_AUTO_ESCALATABLE),
        ],
    )
    def test_row_two_queues_for_review(
        self, override: dict[str, Any], reason: ReviewReason
    ) -> None:
        decision = route_bulletin(self._inputs(**override))
        assert not decision.auto_issue
        assert reason in decision.reasons

    def test_row_three_overrides_row_one(self) -> None:
        """A Critical on a crown jewel satisfies row one and still waits."""
        decision = route_bulletin(self._inputs(tier=Tier.CRITICAL, criticality=Criticality.HIGH))
        assert not decision.auto_issue
        assert decision.mandatory_review
        assert ReviewReason.CROWN_JEWEL in decision.reasons

    def test_tenant_policy_can_decline_automation(self) -> None:
        """ "Under tenant policy" - the client's call, not the platform's."""
        decision = route_bulletin(self._inputs(automation_policy=AutomationPolicy.REVIEW_ALL))
        assert not decision.auto_issue
        assert ReviewReason.TENANT_POLICY in decision.reasons

    def test_an_unexploited_finding_is_not_auto_issued(self) -> None:
        decision = route_bulletin(self._inputs(exploit_status=ExploitStatus.NONE))
        assert not decision.auto_issue

    def test_vendor_confirmation_counts_as_exploited(self) -> None:
        """Spec §7.2 treats it as KEV-equivalent."""
        decision = route_bulletin(
            self._inputs(exploit_status=ExploitStatus.NONE, vendor_confirmed=True)
        )
        assert decision.auto_issue

    def test_every_reason_is_collected(self) -> None:
        """An analyst picking up the queue should see the whole picture."""
        decision = route_bulletin(self._inputs(patch_available=False, exposure_verified=False))
        assert {ReviewReason.NO_PATCH, ReviewReason.EXPOSURE_UNVERIFIED} <= set(decision.reasons)
        assert decision.explain()


class TestTemplateInjection:
    """Spec §8.1: client fields are merged after drafting, never before."""

    def _context(self, **overrides: Any) -> TenantContext:
        fields: dict[str, Any] = {
            "hostname": "vpn.acme.example.com",
            "product": "FortiOS",
            "version": "7.4.1",
            "exposure_class": ExposureClass.INTERNET,
            "criticality": Criticality.HIGH,
            "tier": Tier.CRITICAL,
            "due_at": None,
            "kev_due": datetime(2024, 2, 16, tzinfo=UTC),
            "exposure_verified_at": NOW,
        }
        fields.update(overrides)
        return TenantContext(**fields)

    def test_the_rendered_bulletin_carries_both_halves(self) -> None:
        body = render_bulletin(
            cve_id="CVE-2024-21762",
            draft="Upgrade to 7.4.3 or later.",
            context=self._context(),
        )
        assert "vpn.acme.example.com" in body
        assert "Upgrade to 7.4.3 or later." in body
        assert "CRITICAL" in body

    def test_critical_says_out_of_band(self) -> None:
        body = render_bulletin(cve_id="CVE-1", draft="x", context=self._context(tier=Tier.CRITICAL))
        assert "out-of-band" in body

    def test_the_kev_due_date_is_shown(self) -> None:
        body = render_bulletin(cve_id="CVE-1", draft="x", context=self._context())
        assert "2024-02-16" in body

    def test_verified_exposure_is_stated_as_verified(self) -> None:
        body = render_bulletin(cve_id="CVE-1", draft="x", context=self._context())
        assert "confirmed reachable" in body

    def test_unverified_exposure_says_so(self) -> None:
        body = render_bulletin(
            cve_id="CVE-1",
            draft="x",
            context=self._context(exposure_verified_at=None),
        )
        assert "not yet confirmed" in body

    @pytest.mark.parametrize(
        ("flag", "phrase"),
        [
            (MatchFlag.BACKPORT, "backport"),
            (MatchFlag.CONFIG_DEPENDENT, "specific feature or configuration"),
            (MatchFlag.UNVERIFIED, "not been confirmed by an active check"),
            (MatchFlag.UNPARSEABLE_VERSION, "could not be compared"),
            (MatchFlag.UNBOUNDED_RANGE, "without a version bound"),
        ],
    )
    def test_flags_become_plain_warnings(self, flag: MatchFlag, phrase: str) -> None:
        """A client needs what the flag means, not the flag's name."""
        body = render_bulletin(cve_id="CVE-1", draft="x", context=self._context(flags=(str(flag),)))
        assert phrase in body

    def test_a_fronted_origin_is_explained(self) -> None:
        body = render_bulletin(cve_id="CVE-1", draft="x", context=self._context(waf_detected=True))
        assert "WAF or proxy" in body

    def test_client_side_is_never_called_internet_facing(self) -> None:
        """Spec §6.3."""
        body = render_bulletin(
            cve_id="CVE-1",
            draft="x",
            context=self._context(exposure_class=ExposureClass.CLIENT_SIDE),
        )
        assert "weaponised content" in body
        assert "internet-facing" not in body

    def test_the_bulletin_states_the_privacy_property(self) -> None:
        body = render_bulletin(cve_id="CVE-1", draft="x", context=self._context())
        assert "no host, address or organisation name was sent" in body


class TestDraftType:
    def test_a_model_written_draft_is_distinguishable(self) -> None:
        """Audit evidence: which bulletins a model wrote, and which it did not."""
        assert Draft(text="x", is_model_written=True, model="claude-opus-5-5").is_model_written
        assert not Draft(text="x").is_model_written

    def test_an_unnamed_model_draft_still_counts_as_model_written(self) -> None:
        """Regression: deriving this from `model` made an unnamed draft look
        like a failed one, which blocked auto-issue under §8.2."""
        assert Draft(text="x", is_model_written=True, model=None).is_model_written
