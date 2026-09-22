"""A minimal authoritative-only DNS answer function for use in tests.

This module implements the authoritative side of RFC 1034 section 4.3.2
(with RFC 4592 wildcard semantics) as a pure function: given a
dns.zone.Zone snapshot and a query message, it produces the response
message an authoritative server for that zone would send.  No sockets or
listeners are involved, which makes it convenient for testing
resolver-like code against realistic zone data.

Supported scope (everything else gets an explicit error status):

- Only queries in the zone's class (IN) for types A, AAAA, and CNAME are
  answered.  Other types -- including DNSSEC types and DNAME -- yield
  NOTIMP.
- Recursion is not offered; queries with RD set are REFUSED, and RA is
  never set.
- Non-QUERY opcodes yield NOTIMP; a question count other than one yields
  FORMERR; names outside the zone and classes other than the zone's
  class yield REFUSED.

Answer semantics:

- Exact matches return the requested data with AA set.
- Wildcard matches follow the closest-encloser rules of RFC 4592: the
  wildcard *.<closest encloser> only matches if no closer ancestor of
  the qname exists.  Empty non-terminals (which dnspython does not
  materialize as nodes when loading a zone file) count as existing
  names, so they block wildcard matching and produce NODATA rather than
  a synthesized wildcard answer.
- NXDOMAIN (name does not exist, no wildcard match) and NODATA (name
  exists, type does not) are distinguished; both carry the zone's SOA in
  the authority section and have AA set.
- Queries at or below a delegation point (a non-apex node with an NS
  rdataset) get a referral: AA clear, the NS rdataset in the authority
  section, and only in-bailiwick glue (A/AAAA of nameservers below the
  delegation point that exist in this zone) in the additional section.
  Data below a zone cut is never served, even if present in the zone
  (such occluded data is ignored), and wildcards do not match across a
  cut.
- CNAMEs are chased within the zone only.  If a CNAME target is outside
  the zone or below a delegation point, the chain built so far is
  returned as the answer.  CNAME loops and chains longer than the
  explicit max_cname_chain limit yield SERVFAIL with an empty answer
  section.
"""

import dns.flags
import dns.message
import dns.name
import dns.node
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdataset
import dns.rrset
import dns.zone

#: The default maximum number of CNAME hops followed for one query.
DEFAULT_MAX_CNAME_CHAIN = 8

_SUPPORTED_TYPES = frozenset({dns.rdatatype.A, dns.rdatatype.AAAA, dns.rdatatype.CNAME})

# Locate results.
_EXACT = 0  # the name has a node with rdatasets
_ENT = 1  # the name exists but is an empty non-terminal
_WILDCARD = 2  # the name does not exist, but *.closest-encloser does
_NXDOMAIN = 3  # neither the name nor a matching wildcard exists


def _rrset_from_rdataset(
    name: dns.name.Name, rdataset: dns.rdataset.Rdataset
) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(name, rdataset.rdclass, rdataset.rdtype, rdataset.covers)
    for rd in rdataset:
        rrset.add(rd, rdataset.ttl)
    return rrset


def _existing_names(zone: dns.zone.Zone) -> set[dns.name.Name]:
    """Compute the set of absolute names that exist in the zone.

    A name exists if it has a node in the zone or if it is an empty
    non-terminal, i.e. an ancestor (up to and including the origin) of a
    name that has a node.
    """
    origin = zone.origin
    assert origin is not None
    existing: set[dns.name.Name] = set()
    for name in zone.nodes:
        n = name.derelativize(origin)
        while n.is_subdomain(origin) and n not in existing:
            existing.add(n)
            if n == origin:
                break
            n = n.parent()
    return existing


def _closest_encloser(
    existing: set[dns.name.Name], name: dns.name.Name
) -> dns.name.Name:
    """Return the closest encloser of *name*: its longest existing ancestor."""
    n = name.parent()
    while n not in existing:
        n = n.parent()
    return n


def _locate(
    zone: dns.zone.Zone, existing: set[dns.name.Name], name: dns.name.Name
) -> tuple[int, dns.node.Node | None]:
    """Locate *name* in the zone, applying wildcard rules."""
    if name in existing:
        node = zone.get_node(name)
        if node is None or len(node.rdatasets) == 0:
            return (_ENT, None)
        return (_EXACT, node)
    closest_encloser = _closest_encloser(existing, name)
    wildcard = dns.name.Name((b"*",) + closest_encloser.labels)
    node = zone.get_node(wildcard)
    if node is None or len(node.rdatasets) == 0:
        return (_NXDOMAIN, None)
    return (_WILDCARD, node)


def _find_cut(
    zone: dns.zone.Zone, name: dns.name.Name, origin: dns.name.Name
) -> tuple[dns.name.Name, dns.rdataset.Rdataset] | None:
    """Find the deepest delegation point at or above *name*.

    Returns the cut name and its NS rdataset, or None if there is no
    zone cut between *name* (inclusive) and *origin* (exclusive).
    """
    n = name
    while n != origin:
        node = zone.get_node(n)
        if node is not None:
            ns = node.get_rdataset(zone.rdclass, dns.rdatatype.NS)
            if ns is not None:
                return (n, ns)
        n = n.parent()
    return None


def _referral(
    zone: dns.zone.Zone,
    response: dns.message.Message,
    cut_name: dns.name.Name,
    ns: dns.rdataset.Rdataset,
) -> dns.message.Message:
    """Build a referral response for the delegation at *cut_name*."""
    response.authority.append(_rrset_from_rdataset(cut_name, ns))
    seen: set[tuple[dns.name.Name, dns.rdatatype.RdataType]] = set()
    for rd in ns:
        target = rd.target
        # Only in-bailiwick glue is allowed: the nameserver name must be
        # below the delegation point and have addresses in this zone.
        if not target.is_subdomain(cut_name) or target == cut_name:
            continue
        node = zone.get_node(target)
        if node is None:
            continue
        for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            if (target, rdtype) in seen:
                continue
            glue = node.get_rdataset(zone.rdclass, rdtype)
            if glue is not None:
                seen.add((target, rdtype))
                response.additional.append(_rrset_from_rdataset(target, glue))
    return response


def _negative(
    response: dns.message.Message,
    soa: dns.rrset.RRset | None,
    rcode: dns.rcode.Rcode,
) -> dns.message.Message:
    """Make a negative (NXDOMAIN or NODATA) response."""
    response.set_rcode(rcode)
    if soa is not None:
        response.authority.append(soa)
    response.flags |= dns.flags.AA
    return response


def _servfail(response: dns.message.Message) -> dns.message.Message:
    """Make a SERVFAIL response, discarding any partial answer."""
    response.answer = []
    response.set_rcode(dns.rcode.SERVFAIL)
    return response


def answer_query(
    zone: dns.zone.Zone,
    query: dns.message.QueryMessage,
    max_cname_chain: int = DEFAULT_MAX_CNAME_CHAIN,
) -> dns.message.Message:
    """Compute the authoritative response of *zone* to *query*.

    The zone must have an origin.  The query must not have the QR flag
    set.  *max_cname_chain* is the maximum number of CNAME hops followed
    before failing with SERVFAIL.  Returns the response message.
    """
    if zone.origin is None:
        raise ValueError("zone has no origin")
    origin = zone.origin
    response = dns.message.make_response(query)

    if len(query.question) != 1:
        response.set_rcode(dns.rcode.FORMERR)
        return response
    question = query.question[0]
    if query.opcode() != dns.opcode.QUERY:
        response.set_rcode(dns.rcode.NOTIMP)
        return response
    if question.rdclass != zone.rdclass:
        # We are only authoritative for the zone's class.
        response.set_rcode(dns.rcode.REFUSED)
        return response
    if question.rdtype not in _SUPPORTED_TYPES:
        # Only A, AAAA, and CNAME are supported; DNSSEC types, DNAME, and
        # everything else are explicitly not implemented.
        response.set_rcode(dns.rcode.NOTIMP)
        return response
    if query.flags & dns.flags.RD:
        # Recursion is not offered.
        response.set_rcode(dns.rcode.REFUSED)
        return response
    qname = question.name
    if not qname.is_subdomain(origin):
        response.set_rcode(dns.rcode.REFUSED)
        return response

    # A query at or below a zone cut always gets a referral; we never
    # answer for the delegated subzone, even from occluded in-zone data,
    # and wildcards do not match across the cut.
    cut = _find_cut(zone, qname, origin)
    if cut is not None:
        return _referral(zone, response, cut[0], cut[1])

    existing = _existing_names(zone)
    soa_rdataset = zone.get_rdataset(origin, dns.rdatatype.SOA)
    soa = _rrset_from_rdataset(origin, soa_rdataset) if soa_rdataset else None
    qtype = question.rdtype

    current = qname
    visited = {qname}
    hops = 0
    while True:
        status, node = _locate(zone, existing, current)
        if status == _NXDOMAIN:
            return _negative(response, soa, dns.rcode.NXDOMAIN)
        if status == _ENT:
            return _negative(response, soa, dns.rcode.NOERROR)
        assert node is not None
        rdataset = node.get_rdataset(zone.rdclass, qtype)
        if rdataset is not None:
            # For a wildcard match, the owner name of the synthesized
            # rrset is the qname (i.e. *current*), not the wildcard.
            response.answer.append(_rrset_from_rdataset(current, rdataset))
            response.flags |= dns.flags.AA
            return response
        cname = None
        if qtype != dns.rdatatype.CNAME:
            cname = node.get_rdataset(zone.rdclass, dns.rdatatype.CNAME)
        if cname is None:
            # The name exists but has neither the requested type nor a
            # CNAME: NODATA.
            return _negative(response, soa, dns.rcode.NOERROR)
        response.answer.append(_rrset_from_rdataset(current, cname))
        target = cname[0].target
        hops += 1
        if hops > max_cname_chain or target in visited:
            return _servfail(response)
        visited.add(target)
        if not target.is_subdomain(origin):
            # The CNAME target is outside the zone; return the chain.
            response.flags |= dns.flags.AA
            return response
        if _find_cut(zone, target, origin) is not None:
            # The target is at or below a delegation point; we must not
            # answer for the delegated subzone, so return the chain.
            response.flags |= dns.flags.AA
            return response
        current = target
