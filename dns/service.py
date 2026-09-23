# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Service discovery using SVCB and HTTPS records (RFC 9460).

This module implements the client side of RFC 9460 service discovery.
Given a name, it follows AliasMode chains, filters ServiceMode records
according to the ALPN protocols and SvcParamKeys the caller supports,
resolves target addresses, and returns a list of candidate endpoints
the caller may connect to.  It only makes DNS queries; actually
connecting (e.g. with TCP or TLS) is left to the caller.
"""

import enum
import time
from collections.abc import Iterable, Sequence

import dns.exception
import dns.immutable
import dns.name
import dns.rdatatype
import dns.rdtypes.svcbbase


class AliasLoop(dns.exception.DNSException):
    """An SVCB/HTTPS AliasMode chain contains a loop."""


class TooManyAliases(dns.exception.DNSException):
    """An SVCB/HTTPS AliasMode chain exceeded the maximum number of aliases."""


class AddressSource(enum.Enum):
    """The source of an endpoint address."""

    #: The address was obtained by an A or AAAA query for the target name.
    QUERY = 1
    #: The address was obtained from an ipv4hint or ipv6hint SvcParam.  It
    #: was not resolved by dnspython, and must not be treated as the result
    #: of an address query or as DNSSEC-validated.
    HINT = 2


@dns.immutable.immutable
class Address:
    """An IP address associated with an endpoint, along with its source."""

    def __init__(self, address: str, source: AddressSource):
        self.address = address
        self.source = source

    def __repr__(self):
        return f"<Address {self.address} from {self.source.name}>"


@dns.immutable.immutable
class Endpoint:
    """A candidate service endpoint derived from a ServiceMode SVCB/HTTPS
    record.

    Endpoints are returned in preference order, i.e. sorted by SvcPriority.
    """

    def __init__(
        self,
        name: dns.name.Name,
        port: int | None,
        alpns: Sequence[bytes],
        priority: int,
        addresses: Sequence[Address],
        params: dns.immutable.Dict,
        owner: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
    ):
        #: The target name to connect to, e.g. for use as the TLS SNI or
        #: HTTP ":authority"/Host.  A TargetName of "." in the record has
        #: been replaced with the record's owner name, as required by
        #: RFC 9460.
        self.name = name
        #: The port to connect to, from the record's "port" SvcParam, or
        #: the caller-supplied default if the record had none.  May be
        #: None if neither specified a port.
        self.port = port
        #: The ALPN protocol identifiers to offer, the intersection of the
        #: record's "alpn" SvcParam (or the default "http/1.1") with the
        #: caller's supported protocols, in the record's preference order.
        self.alpns = tuple(alpns)
        #: The SvcPriority of the record this endpoint was derived from.
        self.priority = priority
        #: The addresses of the target, each tagged with its AddressSource.
        self.addresses = tuple(addresses)
        #: The full set of SvcParams from the record, including any
        #: parameters unknown to dnspython.
        self.params = params
        #: The owner name of the SVCB/HTTPS record this endpoint was
        #: derived from.
        self.owner = owner
        #: The type of record the endpoint was derived from, e.g.
        #: dns.rdatatype.HTTPS or dns.rdatatype.SVCB.
        self.rdtype = rdtype

    def __repr__(self):
        return (
            f"<Endpoint {self.name} port={self.port} alpns={self.alpns} "
            f"priority={self.priority}>"
        )


# The SvcParamKeys that dnspython itself interprets when building endpoints.
# Callers do not need to declare support for these; any other key a record
# marks as mandatory must be declared by the caller for the record to be
# usable.
_always_supported_params = frozenset(
    [
        dns.rdtypes.svcbbase.ParamKey.MANDATORY,
        dns.rdtypes.svcbbase.ParamKey.ALPN,
        dns.rdtypes.svcbbase.ParamKey.NO_DEFAULT_ALPN,
        dns.rdtypes.svcbbase.ParamKey.PORT,
        dns.rdtypes.svcbbase.ParamKey.IPV4HINT,
        dns.rdtypes.svcbbase.ParamKey.IPV6HINT,
    ]
)

_ParamKey = dns.rdtypes.svcbbase.ParamKey


def _make_alpns(alpn: Iterable[bytes | str]) -> set[bytes]:
    alpns = set()
    for a in alpn:
        if isinstance(a, str):
            a = a.encode()
        alpns.add(bytes(a))
    return alpns


def _make_supported_params(params: Iterable[int | str]) -> set[_ParamKey]:
    supported = set(_always_supported_params)
    for key in params:
        if isinstance(key, str):
            key = key.replace("-", "_")
        supported.add(_ParamKey.make(key))
    return supported


def _find_alias(rrset) -> dns.name.Name | None:
    """Return the AliasMode target of an SVCB/HTTPS rrset, or None if the
    rrset has no AliasMode record."""
    for rdata in rrset:
        if rdata.priority == 0:
            return rdata.target
    return None


def _select_records(rrset, alpns, supported_params):
    """Select usable ServiceMode records from an SVCB/HTTPS rrset.

    Returns a list of (rdata, alpns) tuples, where *alpns* is the
    non-empty intersection of the record's offered ALPN protocols and the
    caller's supported protocols, sorted by SvcPriority.
    """
    selected = []
    for rdata in rrset:
        if rdata.priority == 0:  # pragma: no cover
            # AliasMode records are handled separately, so we cannot
            # see one here; this is just defensive.
            continue
        params = rdata.params
        mandatory = params.get(_ParamKey.MANDATORY)
        if mandatory is not None and any(
            key not in supported_params for key in mandatory.keys
        ):
            # The record requires a parameter the caller doesn't support.
            continue
        alpn_param = params.get(_ParamKey.ALPN)
        if alpn_param is not None:
            offered = alpn_param.ids
        elif _ParamKey.NO_DEFAULT_ALPN in params:  # pragma: no cover
            # A well-formed record cannot have no-default-alpn without
            # alpn, but be defensive.
            continue
        else:
            offered = (b"http/1.1",)
        usable = tuple(a for a in offered if a in alpns)
        if len(usable) == 0:
            continue
        selected.append((rdata, usable))
    selected.sort(key=lambda item: item[0].priority)
    return selected


def _hint_addresses(rdata, addresses, seen):
    for key in (_ParamKey.IPV4HINT, _ParamKey.IPV6HINT):
        param = rdata.params.get(key)
        if param is not None:
            for address in param.addresses:
                if address not in seen:
                    seen.add(address)
                    addresses.append(Address(address, AddressSource.HINT))


def _resolve_addresses_sync(resolver, rdata, target, start, lifetime):
    addresses: list[Address] = []
    seen = set()
    for rdtype in (dns.rdatatype.AAAA, dns.rdatatype.A):
        try:
            answer = resolver.resolve(
                target,
                rdtype,
                raise_on_no_answer=False,
                lifetime=resolver._compute_timeout(start, lifetime),
                search=False,
            )
        except Exception:
            # Address resolution is best-effort; a failure here must not
            # make other records unusable.
            continue
        if answer.rrset is not None:
            for item in answer.rrset:
                if item.address not in seen:
                    seen.add(item.address)
                    addresses.append(Address(item.address, AddressSource.QUERY))
    _hint_addresses(rdata, addresses, seen)
    return addresses


async def _resolve_addresses_async(resolver, rdata, target, start, lifetime, backend):
    addresses: list[Address] = []
    seen = set()
    for rdtype in (dns.rdatatype.AAAA, dns.rdatatype.A):
        try:
            answer = await resolver.resolve(
                target,
                rdtype,
                raise_on_no_answer=False,
                lifetime=resolver._compute_timeout(start, lifetime),
                search=False,
                backend=backend,
            )
        except Exception:
            # Address resolution is best-effort; a failure here must not
            # make other records unusable.
            continue
        if answer.rrset is not None:
            for item in answer.rrset:
                if item.address not in seen:
                    seen.add(item.address)
                    addresses.append(Address(item.address, AddressSource.QUERY))
    _hint_addresses(rdata, addresses, seen)
    return addresses


def _make_endpoint(rdata, target, alpns, addresses, port, owner, rdtype):
    port_param = rdata.params.get(_ParamKey.PORT)
    if port_param is not None:
        port = port_param.port
    return Endpoint(
        target, port, alpns, rdata.priority, addresses, rdata.params, owner, rdtype
    )


def _follow_alias(alias, visited, hops, max_aliases):
    if alias == dns.name.root:
        # An AliasMode TargetName of "." means the service does not
        # exist (RFC 9460 section 2.5).
        return None
    if alias in visited:
        raise AliasLoop(f"alias loop detected at {alias}")
    if hops > max_aliases:
        raise TooManyAliases(f"more than {max_aliases} aliases followed")
    visited.add(alias)
    return alias


def _resolve_service_sync(
    resolver, qname, rdtype, alpn, params, port, max_aliases, lifetime, search
):
    alpns = _make_alpns(alpn)
    supported_params = _make_supported_params(params)
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    if isinstance(qname, str):
        qname = dns.name.from_text(qname)
    start = time.time()
    visited = {qname}
    hops = 0
    first = True
    while True:
        answer = resolver.resolve(
            qname,
            rdtype,
            raise_on_no_answer=False,
            lifetime=resolver._compute_timeout(start, lifetime),
            search=search if first else False,
        )
        first = False
        rrset = answer.rrset
        if rrset is None:
            return []
        alias = _find_alias(rrset)
        if alias is None:
            break
        hops += 1
        qname = _follow_alias(alias, visited, hops, max_aliases)
        if qname is None:
            return []
    owner = rrset.name
    endpoints = []
    for rdata, usable in _select_records(rrset, alpns, supported_params):
        target = rdata.target
        if target == dns.name.root:
            # A ServiceMode TargetName of "." means the owner name
            # (RFC 9460 section 2.5).
            target = owner
        addresses = _resolve_addresses_sync(resolver, rdata, target, start, lifetime)
        endpoints.append(
            _make_endpoint(rdata, target, usable, addresses, port, owner, rdtype)
        )
    return endpoints


async def _resolve_service_async(
    resolver, qname, rdtype, alpn, params, port, max_aliases, lifetime, search, backend
):
    alpns = _make_alpns(alpn)
    supported_params = _make_supported_params(params)
    rdtype = dns.rdatatype.RdataType.make(rdtype)
    if isinstance(qname, str):
        qname = dns.name.from_text(qname)
    start = time.time()
    visited = {qname}
    hops = 0
    first = True
    while True:
        answer = await resolver.resolve(
            qname,
            rdtype,
            raise_on_no_answer=False,
            lifetime=resolver._compute_timeout(start, lifetime),
            search=search if first else False,
            backend=backend,
        )
        first = False
        rrset = answer.rrset
        if rrset is None:
            return []
        alias = _find_alias(rrset)
        if alias is None:
            break
        hops += 1
        qname = _follow_alias(alias, visited, hops, max_aliases)
        if qname is None:
            return []
    owner = rrset.name
    endpoints = []
    for rdata, usable in _select_records(rrset, alpns, supported_params):
        target = rdata.target
        if target == dns.name.root:
            target = owner
        addresses = await _resolve_addresses_async(
            resolver, rdata, target, start, lifetime, backend
        )
        endpoints.append(
            _make_endpoint(rdata, target, usable, addresses, port, owner, rdtype)
        )
    return endpoints
