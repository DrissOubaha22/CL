"""Verification boundaries - spec §6.2.

§6.2 says verification is "limited to the specific host and service named by
a candidate match", is "not broad network scanning" and "performs no
exploitation".  These assert the boundary holds.
"""

from __future__ import annotations

import pytest

from aegis.core.enums import ExposureClass
from aegis.verification.scope import (
    OutOfScope,
    ProbeTarget,
    assert_host_in_scope,
    is_verifiable,
    resolve_in_scope_addresses,
)


class TestHostShape:
    @pytest.mark.parametrize(
        "host",
        [
            "https://example.com",  # a URL, not a host
            "example.com/admin",  # a path
            "10.0.0.0/8",  # a CIDR range
            "a.example.com,b.example.com",  # a list
            "*.example.com",  # a wildcard
            "exa mple.com",
            "",
            "   ",
        ],
    )
    def test_only_a_single_bare_host_is_accepted(self, host: str) -> None:
        """There is no API that takes a range, a list or a URL."""
        with pytest.raises(OutOfScope):
            assert_host_in_scope(host, 443)

    @pytest.mark.parametrize("port", [0, -1, 65536, 99999])
    def test_port_must_be_real(self, port: int) -> None:
        with pytest.raises(OutOfScope):
            assert_host_in_scope("example.com", port)

    @pytest.mark.parametrize(
        "host", ["vpn.example.com", "example.com", "a-b.example.co.uk", "8.8.8.8"]
    )
    def test_public_hosts_pass(self, host: str) -> None:
        assert_host_in_scope(host, 443)


class TestAddressSpace:
    @pytest.mark.parametrize(
        "address",
        [
            "127.0.0.1",  # loopback
            "::1",
            "10.1.2.3",  # RFC1918
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",  # link-local
            "224.0.0.1",  # multicast
            "0.0.0.0",
            "203.0.113.10",  # TEST-NET-3, RFC 5737: not globally routable
            "198.18.0.1",  # benchmarking range, RFC 2544
            "240.0.0.1",  # reserved
        ],
    )
    def test_private_and_reserved_space_is_refused(self, address: str) -> None:
        """§6.1 asks whether a service is reachable *from the internet*."""
        with pytest.raises(OutOfScope):
            assert_host_in_scope(address, 443)

    def test_a_name_resolving_only_into_private_space_is_refused(self) -> None:
        """The check that matters is where packets would actually go."""
        with pytest.raises(OutOfScope, match="out-of-scope"):
            resolve_in_scope_addresses("localhost", 443)

    def test_private_space_can_be_opted_into(self) -> None:
        addresses = resolve_in_scope_addresses("localhost", 443, allow_private=True)
        assert addresses

    def test_an_unresolvable_host_is_out_of_scope_not_a_crash(self) -> None:
        with pytest.raises(OutOfScope, match="does not resolve"):
            resolve_in_scope_addresses("no-such-host.invalid", 443)


class TestExposureScope:
    def test_only_internet_facing_assets_are_verifiable(self) -> None:
        """Spec §6.3: client-side risk is not perimeter reachability."""
        assert is_verifiable(ExposureClass.INTERNET)
        assert not is_verifiable(ExposureClass.INTERNAL)
        assert not is_verifiable(ExposureClass.CLIENT_SIDE)
        assert not is_verifiable(ExposureClass.UNKNOWN)


class TestProbeTarget:
    def test_a_target_names_exactly_one_service(self) -> None:
        target = ProbeTarget(host="vpn.example.com", port=443)
        assert str(target) == "vpn.example.com:443"
        # No field accepts a second port or host.
        assert isinstance(target.port, int)


class TestAllowPrivateIsConsistent:
    """The early shape check and the resolution check must agree.

    If ``assert_host_in_scope`` refused a literal private address that
    ``resolve_in_scope_addresses`` would have allowed, a deployment verifying
    an internal footprint by IP could never probe anything.
    """

    def test_a_literal_private_address_is_allowed_when_opted_in(self) -> None:
        assert_host_in_scope("10.1.2.3", 443, allow_private=True)
        assert resolve_in_scope_addresses("127.0.0.1", 443, allow_private=True) == ("127.0.0.1",)

    def test_it_is_still_refused_by_default(self) -> None:
        with pytest.raises(OutOfScope):
            assert_host_in_scope("10.1.2.3", 443)

    def test_shape_rules_still_apply_when_opted_in(self) -> None:
        """Opting into private space does not open the door to ranges."""
        for host in ("10.0.0.0/8", "https://10.1.2.3", "a,b"):
            with pytest.raises(OutOfScope):
                assert_host_in_scope(host, 443, allow_private=True)
