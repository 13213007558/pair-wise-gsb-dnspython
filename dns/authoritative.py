# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Minimal authoritative-only DNS answer generation.

This module provides :func:`answer`, a small authoritative answer
function suitable for embedding in test services.  It takes a
:py:class:`dns.zone.Zone` snapshot and a query message, and produces a
response message, implementing closest-encloser wildcard matching
(RFC 4592), empty non-terminal awareness, delegation referrals with
in-bailiwick glue, and in-zone CNAME chasing.

Only queries in the zone's class for A, AAAA, and CNAME are supported.
DNSSEC, DNAME, and recursion are not supported; out-of-scope requests
get an explicit error status (``NOTIMP`` or ``REFUSED``).
"""

import dataclasses
import enum
from typing import cast

import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.node
import dns.opcode
import dns.rcode
import dns.rdata
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.CNAME
import dns.rdtypes.ANY.NS
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.zone


class Error(dns.exception.DNSException):
    """Base class for dns.authoritative exceptions."""


class CnameLoop(Error):
    """A CNAME loop was detected while generating an answer."""


class CnameChainTooLong(Error):
    """A CNAME chain exceeded the maximum allowed length."""


#: The rdata types this module can generate answers for.
SUPPORTED_TYPES = frozenset(
    {dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.CNAME}
)

_DEFAULT_MAX_CNAME_CHAIN = 16


class _LookupKind(enum.Enum):
    EXACT = 0
    WILDCARD = 1
    EMPTY_NON_TERMINAL = 2
    NXDOMAIN = 3
    DELEGATION = 4
    DNAME = 5
    OUT_OF_ZONE = 6


@dataclasses.dataclass(frozen=True)
class _Lookup:
    # name is the owner name to use for answers, or the zone cut name
    # for referrals.
    kind: _LookupKind
    name: dns.name.Name
    node: dns.node.Node | None


def _zone_names(zone: dns.zone.Zone) -> set[dns.name.Name]:
    origin = zone.origin
    assert origin is not None
    return {name.derelativize(origin) for name in zone.nodes}


def _empty_non_terminals(
    names: set[dns.name.Name], origin: dns.name.Name
) -> set[dns.name.Name]:
    # An empty non-terminal is a name with no node of its own that has
    # descendants in the zone.  Zones loaded from master files do not
    # materialize nodes for such names, so we compute them here.
    ents = set()
    for name in names:
        parent = name.parent()
        while parent != origin and parent.is_subdomain(origin):
            if parent in names:
                break
            ents.add(parent)
            parent = parent.parent()
    return ents


def _is_delegation(
    zone: dns.zone.Zone, name: dns.name.Name, node: dns.node.Node
) -> bool:
    return name != zone.origin and (
        node.get_rdataset(zone.rdclass, dns.rdatatype.NS) is not None
    )


def _has_dname(zone: dns.zone.Zone, node: dns.node.Node) -> bool:
    return node.get_rdataset(zone.rdclass, dns.rdatatype.DNAME) is not None


def _lookup(
    zone: dns.zone.Zone, ents: set[dns.name.Name], qname: dns.name.Name
) -> _Lookup:
    origin = zone.origin
    assert origin is not None
    if not qname.is_subdomain(origin):
        return _Lookup(_LookupKind.OUT_OF_ZONE, qname, None)
    # A zone cut takes precedence over everything at or below it, so
    # check for delegations first.  In particular, this prevents glue
    # records below a cut from being served as authoritative answers.
    name = qname
    while name != origin:
        node = zone.get_node(name)
        if node is not None and _is_delegation(zone, name, node):
            return _Lookup(_LookupKind.DELEGATION, name, node)
        name = name.parent()
    node = zone.get_node(qname)
    if node is not None:
        if _has_dname(zone, node):
            return _Lookup(_LookupKind.DNAME, qname, node)
        return _Lookup(_LookupKind.EXACT, qname, node)
    if qname in ents:
        return _Lookup(_LookupKind.EMPTY_NON_TERMINAL, qname, None)
    # Find the closest encloser: the deepest ancestor of qname that
    # exists in the zone, possibly as an empty non-terminal.
    encloser = qname.parent()
    while True:
        node = zone.get_node(encloser)
        if node is not None:
            if _has_dname(zone, node):
                return _Lookup(_LookupKind.DNAME, encloser, node)
            break
        if encloser in ents or encloser == origin:
            break
        encloser = encloser.parent()
    # The closest encloser exists, but qname does not, so the only
    # possible match is the wildcard directly below the closest
    # encloser (RFC 4592).
    wildcard = zone.get_node(dns.name.from_text("*", encloser))
    if wildcard is not None:
        if _has_dname(zone, wildcard):
            return _Lookup(_LookupKind.DNAME, qname, wildcard)
        return _Lookup(_LookupKind.WILDCARD, qname, wildcard)
    return _Lookup(_LookupKind.NXDOMAIN, qname, None)


def _derelativize(
    zone: dns.zone.Zone, rdataset: dns.rdataset.Rdataset
) -> dns.rdataset.Rdataset:
    # A relativized zone holds relative names in its rdata, so we make
    # a copy of the rdataset with all names made absolute for use in
    # messages.
    origin = zone.origin
    assert origin is not None
    new = dns.rdataset.Rdataset(rdataset.rdclass, rdataset.rdtype)
    for rd in rdataset:
        wire = rd.to_wire(origin=origin)
        new.add(
            dns.rdata.from_wire(rdataset.rdclass, rdataset.rdtype, wire, 0, len(wire))
        )
    new.update_ttl(rdataset.ttl)
    return new


def _make_rrset(
    zone: dns.zone.Zone, name: dns.name.Name, rdataset: dns.rdataset.Rdataset
) -> dns.rrset.RRset:
    if zone.relativize:
        rdataset = _derelativize(zone, rdataset)
    rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype)
    rrset.update(rdataset)
    rrset.ttl = rdataset.ttl
    return rrset


def _add_soa(response: dns.message.Message, zone: dns.zone.Zone) -> None:
    origin = zone.origin
    assert origin is not None
    soa = zone.get_rdataset(origin, dns.rdatatype.SOA)
    if soa is None:
        return
    rrset = _make_rrset(zone, origin, soa)
    # The negative caching TTL is the minimum of the SOA TTL and the
    # SOA MINIMUM field (RFC 2308).
    rrset.ttl = min(soa.ttl, cast(dns.rdtypes.ANY.SOA.SOA, soa[0]).minimum)
    response.authority.append(rrset)


def _add_referral(
    response: dns.message.Message,
    zone: dns.zone.Zone,
    cut: dns.name.Name,
    node: dns.node.Node,
) -> None:
    origin = zone.origin
    assert origin is not None
    ns = node.get_rdataset(zone.rdclass, dns.rdatatype.NS)
    assert ns is not None
    response.authority.append(_make_rrset(zone, cut, ns))
    for rd in ns:
        target = cast(dns.rdtypes.ANY.NS.NS, rd).target.derelativize(origin)
        if target.is_subdomain(cut):
            # The nameserver name is in bailiwick, so add its addresses
            # to the additional section if we have them.
            for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                glue = zone.get_rdataset(target, rdtype)
                if glue is not None:
                    response.additional.append(_make_rrset(zone, target, glue))


def answer(
    zone: dns.zone.Zone,
    query: dns.message.Message,
    max_cname_chain: int = _DEFAULT_MAX_CNAME_CHAIN,
) -> dns.message.Message:
    """Generate an authoritative response to a query.

    The zone is treated as a read-only snapshot.  Only queries in the
    zone's class for A, AAAA, and CNAME are answered; other classes and
    types, non-query opcodes, and DNSSEC requests (the CD bit or the
    EDNS DO bit) get a ``NOTIMP`` response.  Queries with the
    RD bit set get a ``REFUSED`` response, as recursion is not
    offered, as do queries for names outside the zone.  DNAME records
    in the zone also yield ``NOTIMP``.

    Names are matched using closest-encloser rules: wildcards only
    match names below an existing closest encloser, and empty
    non-terminals exist and thus return NODATA rather than matching a
    wildcard or returning NXDOMAIN.  Negative answers (NXDOMAIN and
    NODATA) include the zone's SOA in the authority section with the
    negative caching TTL.  Names at or below a delegation point get a
    referral with the NS RRset in the authority section and in-bailiwick
    glue in the additional section; the AA bit is not set on referrals.

    CNAMEs are only chased within the zone.  If a CNAME target is
    outside the zone or below a delegation point, the chain is kept in
    the answer section and chasing stops with a ``NOERROR``
    response.

    :param zone: The zone snapshot to answer from.
    :type zone: :py:class:`dns.zone.Zone`
    :param query: The query message.
    :type query: :py:class:`dns.message.Message`
    :param max_cname_chain: The maximum number of CNAMEs to follow.
    :type max_cname_chain: int
    :raises CnameLoop: if a CNAME loop is detected.
    :raises CnameChainTooLong: if the CNAME chain exceeds
        *max_cname_chain*.
    :raises ValueError: if the zone has no origin or
        *max_cname_chain* is negative.
    :raises dns.exception.FormError: if *query* is not a query.
    :returns: The response message.
    :rtype: :py:class:`dns.message.Message`
    """

    if zone.origin is None:
        raise ValueError("zone has no origin")
    if max_cname_chain < 0:
        raise ValueError("max_cname_chain must be >= 0")
    response = dns.message.make_response(query)
    if query.opcode() != dns.opcode.QUERY:
        response.set_rcode(dns.rcode.NOTIMP)
        return response
    if len(query.question) != 1:
        response.set_rcode(dns.rcode.FORMERR)
        return response
    question = query.question[0]
    qname = question.name
    qtype = question.rdtype
    if query.flags & dns.flags.RD:
        # Recursion is not offered.
        response.set_rcode(dns.rcode.REFUSED)
        return response
    if question.rdclass != zone.rdclass:
        response.set_rcode(dns.rcode.NOTIMP)
        return response
    if qtype not in SUPPORTED_TYPES:
        # This covers DNAME and DNSSEC types too.
        response.set_rcode(dns.rcode.NOTIMP)
        return response
    if query.flags & dns.flags.CD or (
        query.edns >= 0 and query.ednsflags & dns.flags.DO
    ):
        # DNSSEC is not supported.
        response.set_rcode(dns.rcode.NOTIMP)
        return response

    origin = zone.origin
    ents = _empty_non_terminals(_zone_names(zone), origin)
    response.flags |= dns.flags.AA
    visited = {qname}
    current = qname
    chain = 0
    while True:
        look = _lookup(zone, ents, current)
        if look.kind == _LookupKind.OUT_OF_ZONE:
            if chain == 0:
                # We are not authoritative for the query name.
                response.flags &= ~dns.flags.AA
                response.set_rcode(dns.rcode.REFUSED)
            # Otherwise the name is a cross-zone CNAME target; the
            # chain is kept in the answer and we stop.
            return response
        if look.kind == _LookupKind.DELEGATION:
            if chain == 0:
                response.flags &= ~dns.flags.AA
                assert look.node is not None
                _add_referral(response, zone, look.name, look.node)
            # A CNAME target at or below a zone cut is not followed;
            # we do not answer across delegations.
            return response
        if look.kind == _LookupKind.DNAME:
            # DNAME is not supported.
            response.set_rcode(dns.rcode.NOTIMP)
            return response
        if look.kind == _LookupKind.NXDOMAIN:
            response.set_rcode(dns.rcode.NXDOMAIN)
            _add_soa(response, zone)
            return response
        if look.kind == _LookupKind.EMPTY_NON_TERMINAL:
            # NODATA
            _add_soa(response, zone)
            return response
        node = look.node
        assert node is not None
        rdataset = node.get_rdataset(zone.rdclass, qtype)
        if rdataset is not None:
            response.answer.append(_make_rrset(zone, current, rdataset))
            return response
        cname = node.get_rdataset(zone.rdclass, dns.rdatatype.CNAME)
        if cname is None:
            # NODATA
            _add_soa(response, zone)
            return response
        response.answer.append(_make_rrset(zone, current, cname))
        chain += 1
        if chain > max_cname_chain:
            raise CnameChainTooLong(
                f"CNAME chain exceeds maximum length of {max_cname_chain}"
            )
        target = cast(dns.rdtypes.ANY.CNAME.CNAME, cname[0]).target.derelativize(
            origin
        )
        if target in visited:
            raise CnameLoop(f"CNAME loop detected at {target}")
        visited.add(target)
        current = target
