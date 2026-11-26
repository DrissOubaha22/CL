"""The AI data boundary (spec §8.1, §11).

Spec §8.1 is unambiguous: "The model never receives client-identifying data."
That is enforced twice here, deliberately:

1. **Structurally.** Everything sent to a model is a
   :class:`PublicPayload`, which can only be built from the shared intel
   schema or from fetched public pages.  There is no constructor that takes
   a tenant row, so the ordinary way of writing this code cannot leak.
2. **At runtime.** :class:`PrivacyGuard` scans the assembled payload for the
   tenant identifiers it was told about and refuses the call if it finds
   one.  The structural rule already prevents the obvious mistake; this
   catches the refactor that reintroduces it a year from now.

The second check costs a string scan per request and is worth it: a leak
here is a client's hostnames leaving their boundary, which no amount of
"we were careful" repairs afterwards.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

log = structlog.get_logger(__name__)

__all__ = [
    "PrivacyGuard",
    "PrivacyViolation",
    "PublicPayload",
    "TenantIdentifiers",
]

#: Shapes that are client-identifying wherever they appear.  These are
#: checked even when no tenant identifiers were supplied, because a payload
#: should never contain them at all.
_ALWAYS_FORBIDDEN: tuple[tuple[str, re.Pattern[str]], ...] = (
    # RFC1918 and loopback literals: an internal address is tenant topology.
    (
        "private_ip",
        re.compile(
            r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
        ),
    ),
    # An internal hostname convention: anything ending .internal / .local / .lan
    ("internal_hostname", re.compile(r"\b[\w-]+\.(?:internal|local|lan|corp)\b", re.I)),
)


class PrivacyViolation(RuntimeError):
    """A payload bound for a model contained client-identifying data.

    Raised *before* the request is made.  Never caught and retried: the
    correct response is to fix the caller, not to send a redacted version.
    """

    def __init__(self, kind: str, sample: str) -> None:
        super().__init__(
            f"refusing to send client-identifying data to a model: {kind} ({sample!r})"
        )
        self.kind = kind
        self.sample = sample


@dataclass(frozen=True, slots=True)
class TenantIdentifiers:
    """The strings that identify one tenant, for the runtime check.

    Assembled from the tenant registry and the assets involved in whatever
    is being drafted.  Never sent anywhere - only compared against.
    """

    slug: str | None = None
    name: str | None = None
    hostnames: frozenset[str] = field(default_factory=frozenset)
    addresses: frozenset[str] = field(default_factory=frozenset)

    def terms(self) -> list[tuple[str, str]]:
        """``(kind, value)`` pairs to look for, longest first.

        Short values are skipped: a two-character slug would match inside
        ordinary advisory prose and make every draft fail.
        """
        candidates: list[tuple[str, str]] = []
        if self.slug and len(self.slug) >= 4:
            candidates.append(("tenant_slug", self.slug))
        if self.name and len(self.name) >= 4:
            candidates.append(("tenant_name", self.name))
        candidates.extend(("hostname", host) for host in self.hostnames if host)
        candidates.extend(("address", address) for address in self.addresses if address)
        return sorted(candidates, key=lambda item: -len(item[1]))


@dataclass(frozen=True, slots=True)
class PublicPayload:
    """Text that may be sent to a model.

    Construction is the assertion: callers build one of these from the
    shared intel store or from a fetched public page, and nothing else in
    the codebase accepts a tenant row and returns one.
    """

    #: What this payload is, for logging: "advisory_page", "intel_record".
    kind: str
    text: str
    #: Where the text came from, so a draft can cite it.
    source_url: str | None = None

    def __post_init__(self) -> None:
        if not self.text or not self.text.strip():
            raise ValueError("a public payload must carry text")


class PrivacyGuard:
    """Runtime check that a payload carries no client-identifying data."""

    def __init__(self, identifiers: TenantIdentifiers | None = None) -> None:
        self._identifiers = identifiers or TenantIdentifiers()

    def check(self, *payloads: PublicPayload | str) -> None:
        """Scan every payload, raising on the first violation.

        Raises:
            PrivacyViolation: if a tenant identifier or an always-forbidden
                shape appears in the text.
        """
        for payload in payloads:
            text = payload.text if isinstance(payload, PublicPayload) else payload
            self._check_text(text)

    def _check_text(self, text: str) -> None:
        lowered = text.lower()

        for kind, value in self._identifiers.terms():
            if value.lower() in lowered:
                log.error("ai.privacy_violation", kind=kind)
                raise PrivacyViolation(kind, value)

        for kind, pattern in _ALWAYS_FORBIDDEN:
            found = pattern.search(text)
            if found is not None:
                log.error("ai.privacy_violation", kind=kind)
                raise PrivacyViolation(kind, found.group(0))

    def scrub(self, value: Any) -> Any:  # pragma: no cover - deliberate stub
        """Not provided, on purpose.

        Redacting a payload that should never have contained client data
        hides the bug that produced it.  The only correct response to a
        violation is to fix the caller.
        """
        raise NotImplementedError("payloads are validated, never scrubbed: fix the caller instead")
