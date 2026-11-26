"""Privacy-safe drafting (spec §8.1).

Spec §8.1 gives the shape directly::

    draft    = llm(intel_record_public)   # CVE facts, generic remediation
    bulletin = render(template, draft, tenant=..., exposure=..., tier=...)

The two halves are separate functions here, and the first one's only input
is a :class:`PublicIntelView`, which can be built from an ``intel_record``
and nothing else.  There is no overload that takes an asset, a match or a
tenant: the privacy property is a consequence of the type signature, not of
remembering to be careful.

:func:`draft_public_prose` falls back to a deterministic summary when no
model is available.  A deployment that cannot reach a model - or has turned
it off - still issues bulletins; they are plainer, and they say so.
"""

from __future__ import annotations

from dataclasses import dataclass

import structlog

from aegis.ai.client import LlmClient, LlmError, LlmUnavailable
from aegis.ai.privacy import PublicPayload
from aegis.ai.prompts import BULLETIN_DRAFT_INSTRUCTIONS, BULLETIN_DRAFT_SYSTEM
from aegis.core.enums import ExploitStatus
from aegis.db.models import IntelRecord

log = structlog.get_logger(__name__)

__all__ = ["Draft", "PublicIntelView", "draft_public_prose", "public_view_of"]


@dataclass(frozen=True, slots=True)
class PublicIntelView:
    """The public facts about one CVE - everything a draft may be based on.

    Built only by :func:`public_view_of`, from the shared intel store.  That
    store holds no tenant data at all (spec §2), which is what makes this
    type safe to hand to a model.
    """

    cve_id: str
    exploit_status: ExploitStatus
    on_kev: bool
    vendor_confirmed: bool
    ransomware: bool
    patch_available: bool
    config_dependent: bool
    cvss: float | None
    epss: float | None
    cwe: tuple[str, ...]
    description: str | None
    affected_summary: tuple[str, ...]

    def as_payload(self) -> PublicPayload:
        """Render the facts as the text a model is given."""
        lines = [f"CVE: {self.cve_id}"]
        if self.cvss is not None:
            lines.append(f"CVSS base score: {self.cvss}")
        if self.epss is not None:
            lines.append(f"EPSS (30-day exploitation probability): {self.epss:.4f}")
        lines.append(f"Exploitation status: {self.exploit_status}")
        lines.append(f"On the CISA KEV catalogue: {_yes_no(self.on_kev)}")
        lines.append(f"Vendor confirms exploitation: {_yes_no(self.vendor_confirmed)}")
        lines.append(f"Linked to ransomware campaigns: {_yes_no(self.ransomware)}")
        lines.append(f"Patch available: {_yes_no(self.patch_available)}")
        if self.config_dependent:
            lines.append("Exploitability depends on a specific feature or configuration.")
        if self.cwe:
            lines.append(f"Weakness types: {', '.join(self.cwe)}")
        if self.affected_summary:
            lines.append("Affected versions:")
            lines.extend(f"  - {item}" for item in self.affected_summary)
        if self.description:
            lines.append(f"\nPublished description:\n{self.description}")

        return PublicPayload(kind="intel_record", text="\n".join(lines))


@dataclass(slots=True)
class Draft:
    """Prose about a CVE, carrying no client data."""

    text: str
    #: Whether a model produced this text, as opposed to the deterministic
    #: fallback.  Deliberately separate from ``model``: whether a model
    #: wrote it and whether the caller recorded *which* model are different
    #: facts, and conflating them made an unnamed model draft look like a
    #: failed one - which then blocked auto-issue under §8.2.
    is_model_written: bool = False
    #: The model's name, when the caller supplied one.  Stored on the
    #: bulletin for audit.
    model: str | None = None


def public_view_of(
    record: IntelRecord, *, affected_summary: list[str] | None = None
) -> PublicIntelView:
    """Build the public view of a CVE from the shared intel store.

    This is the only constructor of :class:`PublicIntelView`, and its only
    argument is an ``intel_record``.  Nothing tenant-scoped can reach it.
    """
    return PublicIntelView(
        cve_id=record.cve_id,
        exploit_status=ExploitStatus(record.exploit_status),
        on_kev=record.on_kev,
        vendor_confirmed=record.vendor_confirmed,
        ransomware=record.ransomware,
        patch_available=record.patch_available,
        config_dependent=record.config_dependent,
        cvss=record.cvss,
        epss=record.epss,
        cwe=tuple(record.cwe or ()),
        description=record.description,
        affected_summary=tuple(affected_summary or ()),
    )


def draft_public_prose(
    view: PublicIntelView, *, llm: LlmClient | None, model_name: str | None = None
) -> Draft:
    """Draft the explanation and remediation for a CVE (spec §8.1).

    Args:
        view: The public facts.  The only thing that reaches the model.
        llm: The model client, or ``None`` to use the deterministic
            fallback.
        model_name: Recorded on the draft for audit.

    Returns:
        The draft.  Never raises for a model failure: a bulletin that says
        less is better than a finding nobody is told about.
    """
    payload = view.as_payload()

    if llm is None:
        return Draft(text=_deterministic_prose(view))

    try:
        text = llm.draft(
            system=BULLETIN_DRAFT_SYSTEM,
            payload=payload,
            instructions=BULLETIN_DRAFT_INSTRUCTIONS,
        )
    except (LlmError, LlmUnavailable) as exc:
        log.warning("bulletin.draft_failed", cve=view.cve_id, error=str(exc))
        return Draft(text=_deterministic_prose(view))

    if not text.strip():
        log.warning("bulletin.draft_empty", cve=view.cve_id)
        return Draft(text=_deterministic_prose(view))

    return Draft(text=text.strip(), is_model_written=True, model=model_name)


def _deterministic_prose(view: PublicIntelView) -> str:
    """A plain summary of the same facts, with no model involved.

    Deliberately flat: it states what is known and stops.  Its job is to
    keep the pipeline working when the model is unavailable, not to imitate
    the model's prose.
    """
    sentences: list[str] = []

    if view.description:
        sentences.append(view.description.strip())
    else:
        sentences.append(f"{view.cve_id} affects the product listed below.")

    if view.exploit_status is ExploitStatus.ACTIVE:
        if view.on_kev and view.vendor_confirmed:
            sentences.append(
                "Exploitation is confirmed both by the vendor and by CISA's "
                "Known Exploited Vulnerabilities catalogue."
            )
        elif view.on_kev:
            sentences.append(
                "CISA lists this CVE in the Known Exploited Vulnerabilities "
                "catalogue, so exploitation is confirmed."
            )
        elif view.vendor_confirmed:
            sentences.append("The vendor states this vulnerability is being exploited.")
        else:
            sentences.append("Exploitation has been reported in the wild.")
    elif view.exploit_status is ExploitStatus.POC:
        sentences.append(
            "Public exploit code exists, but exploitation in the wild has not been confirmed."
        )
    else:
        sentences.append("No exploitation has been confirmed.")

    if view.ransomware:
        sentences.append("It has been used in ransomware campaigns.")

    if view.affected_summary:
        sentences.append(f"Affected versions: {'; '.join(view.affected_summary)}.")

    if view.patch_available:
        sentences.append("A vendor patch is available; upgrade to a fixed release.")
    else:
        sentences.append(
            "No vendor patch is recorded yet. Apply the vendor's mitigations "
            "and restrict access to the affected service until one ships."
        )

    if view.config_dependent:
        sentences.append(
            "The vendor states exploitability depends on a specific feature "
            "or configuration, so confirm whether this deployment is in that "
            "configuration before treating it as exploitable."
        )

    return " ".join(sentences)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
