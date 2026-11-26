"""CPE 2.3 parsing and normalisation (spec §3.2).

The inventory and the intel store both key on CPE, so both sides must agree
on exactly one spelling.  This module provides the formatted-string binding
parser (``cpe:2.3:o:fortinet:fortios:7.4.2:*:*:*:*:*:*:*``), including the
backslash escaping the standard allows inside components.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

__all__ = ["ANY", "NA", "Cpe", "InvalidCpe", "parse_cpe", "same_product"]


class InvalidCpe(ValueError):
    """The string is not a well-formed CPE 2.3 formatted-string binding."""


ANY = "*"
NA = "-"

_PARTS = ("a", "o", "h")
_COMPONENT_NAMES = (
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
)
_EXPECTED_COMPONENTS = len(_COMPONENT_NAMES)

#: Split on unescaped colons only: ``\:`` is a literal colon in a component.
_UNESCAPED_COLON = re.compile(r"(?<!\\):")


@dataclass(frozen=True, slots=True)
class Cpe:
    """A parsed CPE 2.3 well-formed name."""

    part: str
    vendor: str
    product: str
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    language: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY

    def __str__(self) -> str:
        return self.to_string()

    def to_string(self) -> str:
        """Render the canonical formatted-string binding."""
        return "cpe:2.3:" + ":".join(getattr(self, name) for name in _COMPONENT_NAMES)

    @property
    def has_version(self) -> bool:
        return self.version not in (ANY, NA)

    def without_version(self) -> Cpe:
        """The same product with version/update wildcarded.

        This is the form the matching engine joins on: intel states the
        affected range separately, so the product identity must not carry a
        version (spec §5.1).
        """
        return replace(self, version=ANY, update=ANY)

    @property
    def product_key(self) -> tuple[str, str, str, str]:
        """Identity used to join intel against inventory."""
        return (self.part, self.vendor, self.product, self.target_sw)


def _normalise_component(value: str) -> str:
    value = value.strip()
    if not value:
        raise InvalidCpe("empty CPE component")
    return value.lower()


def parse_cpe(value: str) -> Cpe:
    """Parse a CPE 2.3 formatted string.

    Raises:
        InvalidCpe: on a missing prefix, a wrong component count, or a ``part``
            outside ``a``/``o``/``h``.
    """
    if not value or not isinstance(value, str):
        raise InvalidCpe(f"not a CPE string: {value!r}")

    text = value.strip()
    if not text.lower().startswith("cpe:2.3:"):
        raise InvalidCpe(f"only the CPE 2.3 formatted-string binding is supported: {value!r}")

    components = _UNESCAPED_COLON.split(text)[2:]
    if len(components) != _EXPECTED_COMPONENTS:
        raise InvalidCpe(
            f"expected {_EXPECTED_COMPONENTS} components, got {len(components)}: {value!r}"
        )

    fields = [_normalise_component(component) for component in components]
    if fields[0] not in _PARTS:
        raise InvalidCpe(f"invalid CPE part {fields[0]!r} in {value!r}")

    return Cpe(**dict(zip(_COMPONENT_NAMES, fields, strict=True)))


def same_product(left: Cpe, right: Cpe) -> bool:
    """Do two CPEs name the same product, ignoring version?

    ``target_sw`` is compared only when both sides state it, so an inventory
    entry that never recorded the hosting platform still matches advisory
    intel that does.
    """
    if (left.part, left.vendor, left.product) != (
        right.part,
        right.vendor,
        right.product,
    ):
        return False
    if ANY in (left.target_sw, right.target_sw):
        return True
    return left.target_sw == right.target_sw
