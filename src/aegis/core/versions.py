"""Vendor/semver version comparison (spec §5.2).

Matching is done on *ranges*, never equality, so the comparison has to order
the version strings vendors actually publish: ``7.4.2``, ``7.4.2b``,
``10.0.1_build1234``, ``2.0.0-beta.1``, ``v1.2``.

Two conventions collide in the wild, resolved by three rules applied in
order to each alphabetic token:

* Glued to a digit (``7.4.2b``) - vendor patch letter, sorts *above* the bare
  release.
* A known marker word - ``beta``/``rc``/``alpha``... sort *below* the release,
  ``build``/``patch``/``sp``/``hotfix``... sort *above* it, whatever the
  separator.  So ``10.0.1_build1234`` > ``10.0.1`` but ``2.0.0-beta`` < ``2.0.0``.
* Anything else - a hyphen introduces a pre-release (semver); any other
  separator introduces a post-release.

A string we cannot order raises :class:`UnparseableVersion`.  Per spec §5.2
callers downgrade match confidence on that rather than asserting a match.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import total_ordering

__all__ = [
    "UnparseableVersion",
    "Version",
    "compare",
    "parse_version",
    "version_in_range",
]


class UnparseableVersion(ValueError):
    """The version string carries no orderable information."""


# Token kinds, in ascending order of precedence at the same position.
_PRE = 0  # separated alphabetic token: pre-release
_NUM = 1  # numeric token
_POST = 2  # alphabetic token glued to a digit: vendor patch letter

_SEPARATORS = re.compile(r"([.\-_+~\s/]+)")
_SPLIT_ALNUM = re.compile(r"(\d+|[A-Za-z]+)")

#: Marker words that denote work *before* the named release.
_PRERELEASE_WORDS = frozenset(
    {
        "a",
        "alpha",
        "b",
        "beta",
        "c",
        "cr",
        "dev",
        "ea",
        "m",
        "milestone",
        "pre",
        "preview",
        "rc",
        "snapshot",
    }
)
#: Marker words that denote work *after* the named release.
_POSTRELEASE_WORDS = frozenset(
    {
        "build",
        "fix",
        "hf",
        "hotfix",
        "maint",
        "p",
        "patch",
        "post",
        "r",
        "rev",
        "revision",
        "sp",
        "u",
        "update",
    }
)

#: Placeholders that mean "no version information", not "version zero".
_WILDCARDS = frozenset({"", "*", "-", "n/a", "na", "none", "unknown", "any", "all", "any_version"})

_Token = tuple[int, int, str]
#: Padding used when one version has fewer tokens than the other; equivalent
#: to a trailing ``.0`` so that ``1.2`` == ``1.2.0``.
_PAD: _Token = (_NUM, 0, "")


@total_ordering
@dataclass(frozen=True, slots=True)
class Version:
    """An ordered vendor version."""

    raw: str
    tokens: tuple[_Token, ...]

    def __str__(self) -> str:
        return self.raw

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        return _key_pair(self, other)[0] == _key_pair(self, other)[1]

    def __lt__(self, other: Version) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        left, right = _key_pair(self, other)
        return left < right

    def __hash__(self) -> int:
        # Equality ignores trailing zero padding, so the hash must too.
        trimmed = list(self.tokens)
        while trimmed and trimmed[-1] == _PAD:
            trimmed.pop()
        return hash(tuple(trimmed))


def _key_pair(left: Version, right: Version) -> tuple[tuple[_Token, ...], tuple[_Token, ...]]:
    """Pad both token lists to equal length for positional comparison."""
    width = max(len(left.tokens), len(right.tokens))
    return (
        left.tokens + (_PAD,) * (width - len(left.tokens)),
        right.tokens + (_PAD,) * (width - len(right.tokens)),
    )


def _alpha_kind(word: str, glued_to_digit: bool, separator: str) -> int:
    """Decide whether an alphabetic token is a pre- or post-release marker."""
    if glued_to_digit:
        return _POST
    if word in _PRERELEASE_WORDS:
        return _PRE
    if word in _POSTRELEASE_WORDS:
        return _POST
    # Semver reserves the hyphen for pre-releases; other separators read as
    # vendor build/patch metadata.
    return _PRE if "-" in separator else _POST


def parse_version(value: str) -> Version:
    """Parse ``value`` into an orderable :class:`Version`.

    Raises:
        UnparseableVersion: if the string is empty, a wildcard placeholder, or
            contains no digit at all.
    """
    if value is None:  # defensive: feeds do emit nulls
        raise UnparseableVersion("version is None")

    raw = value.strip()
    if raw.lower() in _WILDCARDS:
        raise UnparseableVersion(f"wildcard or empty version: {value!r}")

    # Strip a leading "v" / "V" marker, but only when a digit follows.
    candidate = raw[1:] if re.match(r"^[vV]\d", raw) else raw

    tokens: list[_Token] = []
    # ``re.split`` with a capturing group yields [segment, sep, segment, ...].
    parts = _SEPARATORS.split(candidate)
    separator = ""
    for index, part in enumerate(parts):
        if index % 2:  # this part is the separator before the next segment
            separator = part
            continue
        if not part:
            continue
        previous_was_numeric = False
        for piece in _SPLIT_ALNUM.findall(part):
            if piece.isdigit():
                tokens.append((_NUM, int(piece), ""))
                previous_was_numeric = True
            else:
                word = piece.lower()
                tokens.append((_alpha_kind(word, previous_was_numeric, separator), 0, word))
                previous_was_numeric = False

    if not any(kind == _NUM for kind, _, _ in tokens):
        raise UnparseableVersion(f"no numeric component in version: {value!r}")

    return Version(raw=raw, tokens=tuple(tokens))


def compare(left: str, right: str) -> int:
    """Return -1, 0 or 1 ordering two version strings."""
    a, b = parse_version(left), parse_version(right)
    if a < b:
        return -1
    return 1 if b < a else 0


def version_in_range(
    version: str,
    *,
    exact: str | None = None,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
) -> bool:
    """Is ``version`` inside the NVD-style range?

    An ``exact`` bound short-circuits the comparison.  With no bound at all
    the range covers every version of the product, which NVD does emit for
    "all versions affected" advisories.

    Raises:
        UnparseableVersion: if ``version`` or any supplied bound cannot be
            ordered.  Callers must treat this as *needs verification*, not as
            a match (spec §5.2).
    """
    target = parse_version(version)

    if exact is not None:
        return target == parse_version(exact)

    if start_including is not None and target < parse_version(start_including):
        return False
    if start_excluding is not None and target <= parse_version(start_excluding):
        return False
    if end_including is not None and parse_version(end_including) < target:
        return False
    # Kept as four symmetric guards rather than one negated expression: each
    # bound reads the same way, and a fifth is easy to add correctly.
    if end_excluding is not None and parse_version(end_excluding) <= target:  # noqa: SIM103
        return False
    return True
