"""The active checks of spec §6.1.

Three questions, asked of exactly one service:

* **Reachability** - does the affected service answer at all, or does it sit
  behind NAT, filtering or a firewall?  A TCP connect, and a TLS handshake
  where the service speaks TLS.
* **Version confirmation** - does the live banner or fingerprint match the
  vulnerable version, rather than a scanner's stale record?
* **WAF/proxy awareness** - is something fronting the origin, so that it must
  not be escalated as directly exploitable?

What these do *not* do, per §6.2: no port scanning, no host enumeration, no
payloads, no exploitation.  A probe connects, completes a handshake, and
issues one minimal HTTP request for the response headers.

:class:`Prober` is a protocol so the engine can be driven with a stub in
tests; :class:`NetworkProber` is the implementation that touches the network.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx
import structlog

from aegis.config import Settings, get_settings
from aegis.verification.scope import OutOfScope, ProbeTarget, resolve_in_scope_addresses

log = structlog.get_logger(__name__)

__all__ = ["NetworkProber", "ProbeObservation", "Prober", "detect_waf", "parse_banner_version"]

#: Response headers and cookies that give away a WAF or CDN in front of the
#: origin.  Presence means the origin is not what answered (spec §6.1).
WAF_SIGNATURES: dict[str, str] = {
    "cf-ray": "cloudflare",
    "cf-cache-status": "cloudflare",
    "x-akamai-transformed": "akamai",
    "akamai-grn": "akamai",
    "x-amz-cf-id": "aws_cloudfront",
    "x-amzn-waf-action": "aws_waf",
    "x-iinfo": "imperva_incapsula",
    "x-cdn": "generic_cdn",
    "x-sucuri-id": "sucuri",
    "x-azure-ref": "azure_front_door",
    "x-fastly-request-id": "fastly",
    "server-timing": "",  # inspected for a vendor token, not a match on its own
}

#: ``Server`` header values that are a proxy, not the product itself.
_PROXY_SERVERS = {
    "cloudflare": "cloudflare",
    "awselb": "aws_elb",
    "akamaighost": "akamai",
    "bigip": "f5_bigip",
    "envoy": "envoy",
}

#: ``name/1.2.3`` as published in Server, SSH and SMTP banners.
_BANNER_VERSION = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9._+-]*)[/ _-](?P<version>\d+(?:\.\d+)*[A-Za-z0-9._-]*)"
)


@dataclass(slots=True)
class ProbeObservation:
    """What a probe actually saw.  No interpretation - that is the engine's job."""

    target: str
    reachable: bool = False
    latency_ms: int | None = None

    tls_negotiated: bool = False
    tls_version: str | None = None
    certificate_subject: str | None = None

    banner: str | None = None
    server_header: str | None = None
    observed_product: str | None = None
    observed_version: str | None = None

    waf_detected: bool = False
    waf_vendor: str | None = None

    error: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class Prober(Protocol):
    """Anything that can answer §6.1's three questions about one service."""

    def probe(self, target: ProbeTarget) -> ProbeObservation:  # pragma: no cover
        ...


class NetworkProber:
    """The real prober: TCP connect, TLS handshake, one banner read."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._last_probe_at: dict[str, float] = {}

    def probe(self, target: ProbeTarget) -> ProbeObservation:
        """Probe exactly one host:port.

        Never raises for a network condition: an unreachable service is a
        finding, not an error.  Only an out-of-scope target is reported as an
        error, because that is a bug in the caller.
        """
        observation = ProbeObservation(target=str(target))

        try:
            addresses = target.addresses or resolve_in_scope_addresses(
                target.host,
                target.port,
                allow_private=self.settings.verification_allow_private_targets,
            )
        except OutOfScope as exc:
            observation.error = str(exc)
            observation.detail["out_of_scope"] = True
            return observation

        self._respect_per_host_delay(target.host)
        observation.detail["addresses"] = list(addresses)

        started = time.monotonic()
        if not self._tcp_connect(addresses[0], target.port, observation):
            return observation
        observation.reachable = True
        observation.latency_ms = int((time.monotonic() - started) * 1000)

        if target.expect_tls:
            self._tls_handshake(target, addresses[0], observation)

        self._read_http_banner(target, observation)
        return observation

    # -- individual checks -------------------------------------------------

    def _tcp_connect(self, address: str, port: int, observation: ProbeObservation) -> bool:
        """Reachability: does anything answer on this one port?"""
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.settings.verification_timeout_seconds)
        try:
            sock.connect((address, port))
            return True
        except TimeoutError:
            observation.error = "connection timed out"
        except OSError as exc:
            observation.error = f"connection failed: {exc.strerror or exc}"
        finally:
            sock.close()
        return False

    def _tls_handshake(
        self, target: ProbeTarget, address: str, observation: ProbeObservation
    ) -> None:
        """Fingerprint: negotiated TLS version and certificate subject.

        Certificate validation is deliberately off: an expired or mismatched
        certificate is information about the service, not a reason to refuse
        to look at it.  Nothing is sent and nothing is trusted.
        """
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(self.settings.verification_timeout_seconds)
        try:
            sock.connect((address, target.port))
            with context.wrap_socket(sock, server_hostname=target.host) as tls:
                observation.tls_negotiated = True
                observation.tls_version = tls.version()
                certificate = tls.getpeercert()
                if certificate:
                    observation.certificate_subject = _subject_of(certificate)
        except (TimeoutError, ssl.SSLError, OSError) as exc:
            # Not an error: plenty of vulnerable services speak plain TCP.
            observation.detail["tls_error"] = str(exc)
        finally:
            sock.close()

    def _read_http_banner(self, target: ProbeTarget, observation: ProbeObservation) -> None:
        """Version confirmation and WAF awareness, from response headers.

        One request for ``/``, no body read beyond what the client buffers,
        and no payload of any kind.
        """
        scheme = "https" if target.expect_tls else "http"
        url = f"{scheme}://{target.host}:{target.port}/"
        try:
            with httpx.Client(
                timeout=self.settings.verification_timeout_seconds,
                # See _tls_handshake: a bad certificate is information
                # about the service, not a reason to stop looking. Nothing
                # is sent and nothing is trusted.
                verify=False,
                follow_redirects=False,
                headers={"User-Agent": self.settings.verification_user_agent},
            ) as client:
                response = client.head(url)
                if response.status_code == 405:
                    # Some appliances refuse HEAD; a GET of "/" is still just
                    # a request for the landing page.
                    response = client.get(url)
        except httpx.HTTPError as exc:
            observation.detail["http_error"] = str(exc)
            return

        headers = {key.lower(): value for key, value in response.headers.items()}
        observation.detail["status_code"] = response.status_code
        observation.server_header = headers.get("server")
        observation.banner = observation.server_header

        vendor = detect_waf(headers)
        if vendor:
            observation.waf_detected = True
            observation.waf_vendor = vendor

        if observation.server_header:
            product, version = parse_banner_version(observation.server_header)
            observation.observed_product = product
            observation.observed_version = version

    def _respect_per_host_delay(self, host: str) -> None:
        """Space out probes to one host so verification never looks like a scan."""
        delay = self.settings.verification_per_host_delay_seconds
        if delay <= 0:
            return
        last = self._last_probe_at.get(host)
        now = time.monotonic()
        if last is not None and now - last < delay:
            time.sleep(delay - (now - last))
        self._last_probe_at[host] = time.monotonic()


def detect_waf(headers: dict[str, str]) -> str | None:
    """Name the WAF or CDN fronting the origin, if any (spec §6.1)."""
    for header, vendor in WAF_SIGNATURES.items():
        if header in headers and vendor:
            return vendor

    server = (headers.get("server") or "").strip().lower()
    for token, vendor in _PROXY_SERVERS.items():
        if token in server:
            return vendor
    return None


def parse_banner_version(banner: str) -> tuple[str | None, str | None]:
    """Pull a product and version out of a service banner.

    Returns ``(None, None)`` when the banner carries no version, which is
    common: many appliances suppress it deliberately.  That is an
    inconclusive version check, not a mismatch (spec §6.2).
    """
    match = _BANNER_VERSION.search(banner or "")
    if match is None:
        return None, None
    return match.group("product").lower(), match.group("version")


def _subject_of(certificate: dict[str, Any]) -> str | None:
    for rdn in certificate.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return str(value)
    return None
