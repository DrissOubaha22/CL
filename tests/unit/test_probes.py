"""Probe mechanics - spec §6.1."""

from __future__ import annotations

import httpx
import pytest
import respx

from aegis.config import Settings
from aegis.verification.probes import (
    NetworkProber,
    ProbeObservation,
    detect_waf,
    parse_banner_version,
)
from aegis.verification.scope import ProbeTarget


class TestWafDetection:
    @pytest.mark.parametrize(
        ("headers", "expected"),
        [
            ({"cf-ray": "abc123"}, "cloudflare"),
            ({"cf-cache-status": "HIT"}, "cloudflare"),
            ({"x-iinfo": "9-1-2"}, "imperva_incapsula"),
            ({"x-amzn-waf-action": "block"}, "aws_waf"),
            ({"x-akamai-transformed": "9"}, "akamai"),
            ({"x-sucuri-id": "1"}, "sucuri"),
            ({"server": "cloudflare"}, "cloudflare"),
            ({"server": "awselb/2.0"}, "aws_elb"),
            ({"server": "BigIP"}, "f5_bigip"),
        ],
    )
    def test_known_fronting_is_named(self, headers: dict[str, str], expected: str) -> None:
        assert detect_waf(headers) == expected

    @pytest.mark.parametrize(
        "headers",
        [
            {"server": "nginx/1.24.0"},
            {"server": "Apache/2.4.58"},
            {"content-type": "text/html"},
            {},
        ],
    )
    def test_an_origin_answering_directly_is_not_flagged(self, headers: dict[str, str]) -> None:
        assert detect_waf(headers) is None

    def test_an_empty_signature_is_not_a_match_on_its_own(self) -> None:
        """``server-timing`` appears on plenty of origins."""
        assert detect_waf({"server-timing": "cdn-cache; desc=HIT"}) is None


class TestBannerVersion:
    @pytest.mark.parametrize(
        ("banner", "product", "version"),
        [
            ("nginx/1.24.0", "nginx", "1.24.0"),
            ("Apache/2.4.58 (Debian)", "apache", "2.4.58"),
            ("Microsoft-IIS/10.0", "microsoft-iis", "10.0"),
            ("openssh_9.3", "openssh", "9.3"),
            ("FortiOS/7.4.1", "fortios", "7.4.1"),
        ],
    )
    def test_product_and_version_are_extracted(
        self, banner: str, product: str, version: str
    ) -> None:
        assert parse_banner_version(banner) == (product, version)

    @pytest.mark.parametrize("banner", ["FortiGate", "Apache", "", "Server"])
    def test_a_banner_without_a_version_yields_nothing(self, banner: str) -> None:
        """Many appliances suppress the version deliberately.

        That is an inconclusive version check, not a mismatch (spec §6.2).
        """
        assert parse_banner_version(banner) == (None, None)


class TestNetworkProberScope:
    @pytest.fixture
    def prober(self) -> NetworkProber:
        return NetworkProber(
            settings=Settings(
                verification_timeout_seconds=1.0,
                verification_per_host_delay_seconds=0.0,
            )
        )

    def test_an_out_of_scope_target_is_reported_not_probed(self, prober: NetworkProber) -> None:
        """A private target is a caller bug, so it is an error, not a finding."""
        observation = prober.probe(ProbeTarget(host="10.1.2.3", port=443))

        assert observation.error is not None
        assert observation.detail["out_of_scope"] is True
        assert observation.reachable is False

    def test_a_malformed_target_never_touches_the_network(self, prober: NetworkProber) -> None:
        observation = prober.probe(ProbeTarget(host="https://evil.test", port=443))
        assert observation.detail["out_of_scope"] is True


class TestBannerRead:
    """The HTTP read issues one request for the landing page, no payload."""

    @respx.mock
    def test_reads_server_header_and_waf_signature(self) -> None:
        route = respx.head("https://vpn.example.com:443/").mock(
            return_value=httpx.Response(200, headers={"Server": "FortiOS/7.4.1", "cf-ray": "abc"})
        )
        prober = NetworkProber(settings=Settings(verification_per_host_delay_seconds=0.0))
        observation = ProbeObservation(target="vpn.example.com:443")
        prober._read_http_banner(ProbeTarget(host="vpn.example.com", port=443), observation)

        assert route.called
        assert observation.server_header == "FortiOS/7.4.1"
        assert observation.observed_version == "7.4.1"
        assert observation.waf_detected is True
        assert observation.waf_vendor == "cloudflare"

    @respx.mock
    def test_falls_back_to_get_when_head_is_refused(self) -> None:
        """Some appliances answer 405 to HEAD."""
        respx.head("https://vpn.example.com:443/").mock(return_value=httpx.Response(405))
        get_route = respx.get("https://vpn.example.com:443/").mock(
            return_value=httpx.Response(200, headers={"Server": "nginx/1.24.0"})
        )
        prober = NetworkProber(settings=Settings(verification_per_host_delay_seconds=0.0))
        observation = ProbeObservation(target="vpn.example.com:443")
        prober._read_http_banner(ProbeTarget(host="vpn.example.com", port=443), observation)

        assert get_route.called
        assert observation.observed_version == "1.24.0"

    @respx.mock
    def test_a_transport_failure_is_recorded_not_raised(self) -> None:
        respx.head("https://vpn.example.com:443/").mock(side_effect=httpx.ConnectError("reset"))
        prober = NetworkProber(settings=Settings(verification_per_host_delay_seconds=0.0))
        observation = ProbeObservation(target="vpn.example.com:443")
        prober._read_http_banner(ProbeTarget(host="vpn.example.com", port=443), observation)

        assert "http_error" in observation.detail
        assert observation.server_header is None


class TestTcpReachability:
    """The socket path, against a real listener on loopback.

    Loopback is normally out of scope (§6.1 asks about internet
    reachability); these opt in explicitly, which is the same switch a
    deployment verifying an internal footprint would use.
    """

    @pytest.fixture
    def listener(self):
        import socket as socket_module

        server = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
        server.setsockopt(socket_module.SOL_SOCKET, socket_module.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        yield server.getsockname()[1]
        server.close()

    @pytest.fixture
    def prober(self) -> NetworkProber:
        return NetworkProber(
            settings=Settings(
                verification_timeout_seconds=2.0,
                verification_per_host_delay_seconds=0.0,
                verification_allow_private_targets=True,
            )
        )

    def test_a_listening_port_is_reachable(self, prober: NetworkProber, listener: int) -> None:
        observation = ProbeObservation(target=f"127.0.0.1:{listener}")
        assert prober._tcp_connect("127.0.0.1", listener, observation) is True
        assert observation.error is None

    def test_a_closed_port_is_not_reachable(self, prober: NetworkProber) -> None:
        """What §6.1 calls NAT/filtering looks exactly like this."""
        observation = ProbeObservation(target="127.0.0.1:1")
        assert prober._tcp_connect("127.0.0.1", 1, observation) is False
        assert observation.error is not None

    def test_probe_reports_reachability_and_latency(
        self, prober: NetworkProber, listener: int
    ) -> None:
        observation = prober.probe(ProbeTarget(host="127.0.0.1", port=listener, expect_tls=False))
        assert observation.reachable is True
        assert observation.latency_ms is not None
        assert observation.detail["addresses"] == ["127.0.0.1"]

    def test_probe_on_a_dead_port_is_a_finding_not_an_exception(
        self, prober: NetworkProber
    ) -> None:
        observation = prober.probe(ProbeTarget(host="127.0.0.1", port=1, expect_tls=False))
        assert observation.reachable is False
        assert observation.error is not None
        assert observation.detail.get("out_of_scope") is None


class TestPerHostPacing:
    def test_consecutive_probes_to_one_host_are_spaced(self) -> None:
        """So verifying many matches on one appliance never looks like a scan."""
        import time

        prober = NetworkProber(settings=Settings(verification_per_host_delay_seconds=0.2))
        start = time.monotonic()
        prober._respect_per_host_delay("vpn.example.com")
        prober._respect_per_host_delay("vpn.example.com")
        assert time.monotonic() - start >= 0.19

    def test_different_hosts_are_not_delayed_by_each_other(self) -> None:
        import time

        prober = NetworkProber(settings=Settings(verification_per_host_delay_seconds=0.2))
        start = time.monotonic()
        prober._respect_per_host_delay("a.example.com")
        prober._respect_per_host_delay("b.example.com")
        assert time.monotonic() - start < 0.1
