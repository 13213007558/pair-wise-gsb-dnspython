# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""DNS service discovery using SVCB and HTTPS records (RFC 9460).

This module implements the I/O-independent parts of service discovery;
the actual discovery entry points are
:py:meth:`~dns.resolver.Resolver.resolve_service` and
:py:meth:`~dns.asyncresolver.Resolver.resolve_service`.

Discovery returns a list of :py:class:`ServiceEndpoint` candidates the
caller may connect to; it does not itself make any TCP, TLS, or QUIC
connections.
"""

import enum
import socket
from collections.abc import Sequence
from typing import Any

import dns.exception
import dns.immutable
import dns.name
import dns.rdata
import dns.rdatatype
from dns.rdtypes.svcbbase import ParamKey

#: The default maximum number of AliasMode records that will be followed
#: during service discovery.
DEFAULT_MAX_ALIASES = 8


class AliasLoop(dns.exception.DNSException):
    """The SVCB/HTTPS AliasMode chain contains a loop."""


class TooManyAliases(dns.exception.DNSException):
    """The SVCB/HTTPS AliasMode chain exceeded the maximum number of aliases."""


class AddressSource(enum.IntEnum):
    """The source of a :py:class:`ServiceAddress`.

    Addresses are either HINT addresses, taken verbatim from the
    ipv4hint/ipv6hint parameters of a SVCB/HTTPS record, or
    LOOKUP addresses, obtained by querying for A/AAAA records of the
    target name.  Note that neither source implies any DNSSEC validation
    of the address.
    """

    HINT = 1
    LOOKUP = 2


@dns.immutable.immutable
class ServiceAddress:
    """An IP address associated with a service endpoint, along with its
    source."""

    def __init__(
        self,
        address: str,
        family: int = socket.AF_UNSPEC,
        source: AddressSource | int = AddressSource.LOOKUP,
    ):
        self.address = address
        self.family = family
        self.source = AddressSource(source)

    def __repr__(self):
        return (
            f"<ServiceAddress {self.address} family={self.family} "
            f"source={self.source.name}>"
        )


@dns.immutable.immutable
class ServiceEndpoint:
    """A candidate endpoint discovered via SVCB/HTTPS service discovery.

    The endpoint describes a service the caller may connect to; no
    connection attempt has been made.
    """

    def __init__(
        self,
        priority: int,
        target: dns.name.Name,
        port: int | None,
        alpn: Sequence[bytes],
        params: Any,
        addresses: Sequence[ServiceAddress],
        owner: dns.name.Name,
    ):
        #: The SvcPriority of the record this endpoint was built from.
        #: Lower values are more preferred.
        self.priority = int(priority)
        #: The effective TargetName; if the record's TargetName was ".",
        #: this is the owner name of the record.
        self.target = target
        #: The port from the port parameter, or None if the
        #: parameter was not present (the caller should use its default
        #: port for the protocol).
        self.port = port
        #: The ALPN protocol identifiers usable by the caller, as a tuple
        #: of bytes.  This is the intersection of the record's alpn
        #: parameter with the caller's supported ALPNs, or the default
        #: ALPN if the record had no alpn parameter.
        self.alpn = tuple(alpn)
        #: All parameters of the record, including unknown optional
        #: parameters, as a dns.immutable.Dict keyed by
        #: dns.rdtypes.svcbbase.ParamKey.
        self.params = params
        #: The addresses associated with the endpoint, each labeled with
        #: its :py:class:`AddressSource`.  Addresses from A/AAAA lookups
        #: of the target name precede any address hints.
        self.addresses = tuple(addresses)
        #: The owner name of the SVCB/HTTPS record this endpoint was
        #: built from, i.e. the final name in any AliasMode chain.
        self.owner = owner

    def __repr__(self):
        return (
            f"<ServiceEndpoint priority={self.priority} target={self.target} "
            f"port={self.port} alpn={self.alpn!r} addresses={list(self.addresses)!r}>"
        )


def _normalize_alpns(alpn):
    if alpn is None:
        return None
    return tuple(dns.rdata.Rdata._as_bytes(a, True, 255, False) for a in alpn)


def _known_param_keys(supported_params):
    # The keys dnspython itself understands, plus any the caller declares.
    known = set(ParamKey)
    if supported_params is not None:
        for key in supported_params:
            known.add(ParamKey.make(key))
    return known


def _alias_target(rrset):
    """Return the AliasMode target of an SVCB/HTTPS RRset, or None if
    the RRset contains no AliasMode records.

    Per RFC 9460, if any AliasMode records are present, ServiceMode
    records in the same RRset are not used.
    """
    for rd in rrset:
        if rd.priority == 0:
            return rd.target
    return None


def _select_records(rrset, alpns, known_keys, default_alpn):
    """Select usable ServiceMode records from an SVCB/HTTPS RRset,
    returning a list of (rdata, alpn) tuples in priority order
    (lowest SvcPriority first).

    A record is unusable if its mandatory parameter lists a key not
    in *known_keys*, or if its ALPN offers do not intersect the caller's
    supported ALPNs.
    """
    selected = []
    for rd in sorted(rrset, key=lambda r: r.priority):
        if rd.priority == 0:
            # AliasMode records are handled separately.
            continue
        mandatory = rd.params.get(ParamKey.MANDATORY)
        if mandatory is not None:
            if any(key not in known_keys for key in mandatory.keys):
                continue
        offered = rd.params.get(ParamKey.ALPN)
        if offered is not None:
            if alpns is None:
                selected_alpns = tuple(offered.ids)
            else:
                selected_alpns = tuple(a for a in offered.ids if a in alpns)
                if len(selected_alpns) == 0:
                    continue
        elif default_alpn is not None:
            # The record has no alpn parameter, so the protocol's default
            # ALPN applies (no-default-alpn cannot be present without alpn).
            if alpns is not None and default_alpn not in alpns:
                continue
            selected_alpns = (default_alpn,)
        else:
            selected_alpns = ()
        selected.append((rd, selected_alpns))
    return selected


def _hint_addresses(rd, family=socket.AF_UNSPEC):
    """Return the address hints of a ServiceMode record as
    ServiceAddress objects with source HINT."""
    addresses = []
    if family in (socket.AF_UNSPEC, socket.AF_INET):
        hint = rd.params.get(ParamKey.IPV4HINT)
        if hint is not None:
            for address in hint.addresses:
                addresses.append(
                    ServiceAddress(address, socket.AF_INET, AddressSource.HINT)
                )
    if family in (socket.AF_UNSPEC, socket.AF_INET6):
        hint = rd.params.get(ParamKey.IPV6HINT)
        if hint is not None:
            for address in hint.addresses:
                addresses.append(
                    ServiceAddress(address, socket.AF_INET6, AddressSource.HINT)
                )
    return addresses


def _prepare(rdtype, alpn, supported_params, default_alpn):
    """Validate and normalize the common resolve_service() arguments."""
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    if rdtype not in (dns.rdatatype.SVCB, dns.rdatatype.HTTPS):
        raise ValueError("rdtype must be SVCB or HTTPS")
    alpns = _normalize_alpns(alpn)
    known_keys = _known_param_keys(supported_params)
    if default_alpn is None and rdtype == dns.rdatatype.HTTPS:
        # RFC 9460 section 9.1: for the HTTPS RR type, the default ALPN
        # is "http/1.1".
        default_alpn = b"http/1.1"
    normalized_default = None
    if default_alpn is not None:
        normalized_default = dns.rdata.Rdata._as_bytes(default_alpn, True, 255, False)
    return (rdtype, alpns, known_keys, normalized_default)
