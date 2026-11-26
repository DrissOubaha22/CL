"""CPE 2.3 parsing - spec §3.2."""

from __future__ import annotations

import pytest

from aegis.core.cpe import ANY, InvalidCpe, parse_cpe, same_product

FORTIOS = "cpe:2.3:o:fortinet:fortios:7.4.2:*:*:*:*:*:*:*"


def test_parses_the_spec_example() -> None:
    cpe = parse_cpe(FORTIOS)
    assert (cpe.part, cpe.vendor, cpe.product, cpe.version) == (
        "o",
        "fortinet",
        "fortios",
        "7.4.2",
    )
    assert cpe.has_version


def test_round_trips_to_canonical_form() -> None:
    assert parse_cpe(FORTIOS).to_string() == FORTIOS


def test_normalises_case() -> None:
    upper = "CPE:2.3:O:Fortinet:FortiOS:7.4.2:*:*:*:*:*:*:*"
    assert parse_cpe(upper).to_string() == FORTIOS


def test_without_version_wildcards_version_and_update() -> None:
    stripped = parse_cpe(FORTIOS).without_version()
    assert stripped.version == ANY
    assert stripped.to_string() == "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"


def test_escaped_colon_is_not_a_separator() -> None:
    cpe = parse_cpe(r"cpe:2.3:a:vendor:pro\:duct:1.0:*:*:*:*:*:*:*")
    assert cpe.product == r"pro\:duct"
    assert cpe.version == "1.0"


def test_wildcard_version_is_not_a_version() -> None:
    assert not parse_cpe("cpe:2.3:a:v:p:*:*:*:*:*:*:*:*").has_version
    assert not parse_cpe("cpe:2.3:a:v:p:-:*:*:*:*:*:*:*").has_version


@pytest.mark.parametrize(
    "value",
    [
        "cpe:/o:fortinet:fortios:7.4.2",  # 2.2 URI binding
        "cpe:2.3:x:v:p:1:*:*:*:*:*:*:*",  # invalid part
        "cpe:2.3:a:v:p",  # truncated
        "cpe:2.3:a:v:p:1:*:*:*:*:*:*:*:extra",  # too many components
        "fortios 7.4.2",
        "",
    ],
)
def test_rejects_malformed_input(value: str) -> None:
    with pytest.raises(InvalidCpe):
        parse_cpe(value)


class TestSameProduct:
    def test_ignores_version(self) -> None:
        assert same_product(
            parse_cpe(FORTIOS),
            parse_cpe("cpe:2.3:o:fortinet:fortios:7.4.8:*:*:*:*:*:*:*"),
        )

    def test_distinguishes_products(self) -> None:
        assert not same_product(
            parse_cpe(FORTIOS),
            parse_cpe("cpe:2.3:o:fortinet:fortimail:7.4.2:*:*:*:*:*:*:*"),
        )

    def test_unstated_target_sw_still_matches(self) -> None:
        """Inventory often never recorded the hosting platform."""
        advisory = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:java:*:*")
        inventory = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
        assert same_product(advisory, inventory)

    def test_conflicting_target_sw_does_not_match(self) -> None:
        java = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:java:*:*")
        dotnet = parse_cpe("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:dotnet:*:*")
        assert not same_product(java, dotnet)
