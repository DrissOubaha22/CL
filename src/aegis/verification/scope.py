"""What exposure verification is allowed to touch (spec §6.2).

Spec §6.2 draws the boundary explicitly: verification is "limited to the
specific host and service named by a candidate match", is "not broad network
scanning", and "performs no exploitation".  This module is where that
boundary is enforced, rather than left to the discipline of each call site.

The rules:

* **One host, one port, per match.** A target is built from a match; there is
  no API that takes a range, a CIDR, or a port list.
* **No private or reserved address space** unless a deployment explicitly
  opts in.  A tenant's internal RFC1918 host is not reachable from the
  internet, so probing it from here answers the wrong question and may reach
  something that is not the tenant's.
* **No exploitation.** The probes connect, complete a TLS handshake and read
  a banner.  Nothing in this package constructs a payload.
* **Internet-facing only.** Internal and client-side assets are out of scope
  by definition (spec §6.3); their risk basis is not perimeter reachability.

Restricting targets to the client's *authorised* footprint is an onboarding
control, not a code one: discovery (§3.1) runs over domains and ranges the
client has declared, and the inventory that results is what names the hosts
reachable from here.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

import structlog

from aegis.core.enums import ExposureClass

log = structlog.get_logger(__name__)

__all__ = [
    "OutOfScope",
    "ProbeTarget",
    "assert_host_in_scope",
    "resolve_in_scope_addresses",
]

#: Ports a verification probe may target.  Anything else needs the match to
#: have named it, and even then it is a single port.
_MAX_PORT = 65535

#: A hostname we are willing to resolve: no schemes, paths or wildcards.
_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


class OutOfScope(ValueError):
    """The target is outside what §6.2 permits verification to touch."""


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    """Exactly one service to probe, named by one match."""

    host: str
    port: int
    #: Addresses the host resolved to, already scope-checked.
    addresses: tuple[str, ...] = ()
    #: Hint from the inventory for how to read the banner.
    expect_tls: bool = True

    def __str__(self) -> str:
        return f"{self.host}:{self.port}"


def assert_host_in_scope(host: str, port: int, *, allow_private: bool = False) -> None:
    """Validate a target before anything is resolved or connected.

    Args:
        host: Bare hostname or literal address.
        port: The single port the match named.
        allow_private: Permit a literal loopback/private/reserved address.
            Must match what :func:`resolve_in_scope_addresses` will be given,
            or a target this accepts would be refused a step later.

    Raises:
        OutOfScope: on an empty or malformed hostname, a port outside
            1-65535, a host given as a URL, CIDR or range, or - unless
            ``allow_private`` - a literal address that is not globally
            routable.
    """
    candidate = (host or "").strip()
    if not candidate:
        raise OutOfScope("no host to probe")
    if not 1 <= port <= _MAX_PORT:
        raise OutOfScope(f"port out of range: {port}")

    lowered = candidate.lower()
    if "://" in lowered or "/" in lowered:
        raise OutOfScope(f"host must be a bare hostname or address, not a URL or range: {host!r}")
    if "," in lowered or "*" in lowered or " " in lowered:
        raise OutOfScope(f"host must name a single service: {host!r}")

    # A literal address is checked directly; a name is checked after
    # resolution, since that is what decides where packets actually go.
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if not _HOSTNAME.match(candidate):
            raise OutOfScope(f"not a valid hostname: {host!r}") from None
        return

    if not allow_private:
        _assert_address_in_scope(address, host)


def _assert_address_in_scope(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address, host: str
) -> None:
    """Refuse anything that is not a globally routable address.

    ``is_global`` is precisely the question §6.1 asks - "is the affected
    service actually reachable from the internet?" - and it covers more than
    an enumeration would: RFC1918, loopback, link-local, multicast,
    documentation ranges (TEST-NET), benchmarking ranges and the rest of the
    IANA special-purpose registry.  The specific checks below only exist to
    give a useful message for the common cases.
    """
    if address.is_loopback:
        raise OutOfScope(f"{host} resolves to loopback {address}")
    if address.is_link_local:
        raise OutOfScope(f"{host} resolves to link-local {address}")
    if address.is_multicast:
        raise OutOfScope(f"{host} resolves to multicast {address}")
    if address.is_private:
        raise OutOfScope(f"{host} resolves to private address {address}")
    if not address.is_global:
        raise OutOfScope(f"{host} resolves to {address}, which is not globally routable")


def resolve_in_scope_addresses(
    host: str, port: int, *, allow_private: bool = False
) -> tuple[str, ...]:
    """Resolve ``host`` and return only addresses verification may reach.

    Resolution happens before connecting so that a name pointing into private
    space is refused rather than probed - the check that matters is where the
    packets would actually go, not what the name looks like.

    Args:
        host: Bare hostname or literal address.
        port: The single port the match named.
        allow_private: Permit loopback/private/link-local targets.  For
            deployments verifying an internal footprint from inside it; off
            by default because §6.1 asks whether a service is reachable *from
            the internet*.

    Raises:
        OutOfScope: if the host is malformed, does not resolve, or resolves
            only to addresses outside scope.
    """
    assert_host_in_scope(host, port, allow_private=allow_private)

    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise OutOfScope(f"{host} does not resolve: {exc}") from exc

    permitted: list[str] = []
    rejected: list[str] = []
    for info in infos:
        address_text = str(info[4][0])
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:  # pragma: no cover - getaddrinfo returns addresses
            continue
        if allow_private:
            permitted.append(address_text)
            continue
        try:
            _assert_address_in_scope(address, host)
        except OutOfScope:
            rejected.append(address_text)
        else:
            permitted.append(address_text)

    if not permitted:
        raise OutOfScope(
            f"{host} resolves only to out-of-scope addresses: {', '.join(rejected) or 'none'}"
        )

    # Deduplicate while keeping resolution order.
    return tuple(dict.fromkeys(permitted))


def is_verifiable(exposure: ExposureClass) -> bool:
    """Is perimeter reachability the right question for this asset?

    Spec §6.3: client-side software is never scored as internet-facing, and
    an internal asset's reachability from the internet is not what its risk
    rests on.
    """
    return exposure is ExposureClass.INTERNET
