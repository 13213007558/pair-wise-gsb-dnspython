# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Offline validation of DNSSEC authenticated denial of existence.

This module implements validation of negative responses (NXDOMAIN and
NODATA) using NSEC records, per RFC 4035 section 5.4 with the applicable
RFC 6840 clarifications.  Validation is "offline": the caller supplies the
question, the response, the trusted DNSKEYs for the zone, and the
validation time.  A successful DNSSEC signature validation only proves
that an NSEC record is unmodified; it does not by itself prove that the
queried name or type does not exist.  The NSEC proof is checked
separately, after the signatures have been verified.

Only plain NSEC is supported.  NSEC3 and establishing a chain of trust
from the root are out of scope.
"""

import enum
import time
from dataclasses import dataclass, field
from typing import cast

import dns.dnssec
import dns.message
import dns.name
import dns.node
import dns.rcode
import dns.rdataset
import dns.rdatatype
import dns.rrset
from dns.exception import UnsupportedAlgorithm, ValidationFailure
from dns.rdtypes.ANY.NSEC import NSEC
from dns.rdtypes.ANY.RRSIG import RRSIG


class NegativeProofStatus(enum.Enum):
    """The outcome of offline negative response validation."""

    VALID = "valid"
    """The denial of existence is proven by validated NSEC records."""

    INSUFFICIENT = "insufficient"
    """The validated NSEC records do not establish the required proof."""

    VALIDATION_FAILED = "validation_failed"
    """Cryptographic validation of a relevant NSEC RRset failed."""


@dataclass(frozen=True)
class NegativeProof:
    """The result of offline negative response validation.

    *status* is a :py:class:`NegativeProofStatus` distinguishing a proven
    negative answer, an insufficient proof, and a validation failure.

    *reason* is a human-readable explanation of the outcome.

    *rrsets* are the NSEC RRsets used to reach the outcome.  For a
    ``VALID`` status these are the RRsets establishing the proof; for
    other statuses they are the validated RRsets that were considered.
    """

    status: NegativeProofStatus
    reason: str
    rrsets: tuple[dns.rrset.RRset, ...] = field(default_factory=tuple)


def _nsec_rdata(rrset: dns.rrset.RRset) -> NSEC:
    return cast(NSEC, rrset[0])


def _nsec_types(nsec: NSEC) -> set[int]:
    """Return the set of rdtypes in an NSEC type bitmap."""
    types = set()
    for window, bitmap in nsec.windows:
        for i, byte in enumerate(bitmap):
            for j in range(8):
                if byte & (0x80 >> j):
                    types.add(window * 256 + i * 8 + j)
    return types


def _covers(
    owner: dns.name.Name, next_name: dns.name.Name, name: dns.name.Name
) -> bool:
    """Does the NSEC interval (owner, next_name) cover name?

    Names are compared using the canonical DNS name order of RFC 4034
    section 6.1.  The wrap-around interval from the last name in the zone
    back to the zone apex is handled, as is the single-name zone where
    the next name equals the owner.
    """
    if owner < next_name:
        return owner < name < next_name
    elif owner == next_name:
        return name != owner
    else:
        return name > owner or name < next_name


def _wildcard_matches(wildcard: dns.name.Name, qname: dns.name.Name) -> bool:
    """Could the wildcard owner name *.ce match qname?"""
    closest_encloser = wildcard.parent()
    return qname != closest_encloser and qname.is_subdomain(closest_encloser)


def _prove_nxdomain(
    qname: dns.name.Name, zone: dns.name.Name, nsecs: list[dns.rrset.RRset]
) -> NegativeProof:
    # Names proven to exist are the NSEC owner names, the NSEC next
    # names, the parents of wildcard owner names (which exist at least
    # as empty non-terminals), and the zone apex.
    existing = {zone}
    for rrset in nsecs:
        owner = rrset.name
        existing.add(owner)
        if owner.is_wild():
            existing.add(owner.parent())
        next_name = _nsec_rdata(rrset).next
        if next_name.is_subdomain(zone):
            existing.add(next_name)
    if qname in existing:
        return NegativeProof(
            NegativeProofStatus.INSUFFICIENT,
            f"the qname {qname} exists",
            tuple(nsecs),
        )

    covering = [
        rrset for rrset in nsecs if _covers(rrset.name, _nsec_rdata(rrset).next, qname)
    ]
    if not covering:
        return NegativeProof(
            NegativeProofStatus.INSUFFICIENT,
            f"no NSEC covers the qname {qname}",
            tuple(nsecs),
        )

    if qname.is_wild():
        # The query is for a wildcard name directly; there is no
        # wildcard synthesis to exclude.
        return NegativeProof(
            NegativeProofStatus.VALID,
            f"the qname {qname} does not exist",
            (covering[0],),
        )

    # The closest encloser is the longest ancestor of the qname proven
    # to exist.  Proving the qname does not exist is not enough; a
    # matching wildcard must also be excluded (RFC 4035 section 5.4).
    closest_encloser = zone
    for name in existing:
        if (
            name != qname
            and qname.is_subdomain(name)
            and len(name) > len(closest_encloser)
        ):
            closest_encloser = name
    wildcard = dns.name.Name((b"*",) + closest_encloser.labels)
    for rrset in nsecs:
        if rrset.name == wildcard:
            return NegativeProof(
                NegativeProofStatus.INSUFFICIENT,
                f"the wildcard {wildcard} exists",
                (rrset,),
            )
    wildcard_covering = [
        rrset
        for rrset in nsecs
        if _covers(rrset.name, _nsec_rdata(rrset).next, wildcard)
    ]
    if not wildcard_covering:
        return NegativeProof(
            NegativeProofStatus.INSUFFICIENT,
            f"no NSEC excludes the wildcard {wildcard}",
            tuple(nsecs),
        )

    if covering[0] is wildcard_covering[0]:
        used = (covering[0],)
    else:
        used = (covering[0], wildcard_covering[0])
    return NegativeProof(
        NegativeProofStatus.VALID,
        f"the qname {qname} does not exist and the wildcard {wildcard} is excluded",
        used,
    )


def _prove_nodata(
    qname: dns.name.Name,
    qtype: dns.rdatatype.RdataType,
    zone: dns.name.Name,
    nsecs: list[dns.rrset.RRset],
) -> NegativeProof:
    for rrset in nsecs:
        if rrset.name == qname:
            types = _nsec_types(_nsec_rdata(rrset))
            # An NSEC at a delegation point (NS set, SOA clear, not the
            # apex) only proves the absence of DS; it says nothing about
            # types in the child zone (RFC 6840 section 4.1).
            is_delegation = (
                qname != zone
                and dns.rdatatype.NS in types
                and dns.rdatatype.SOA not in types
            )
            if is_delegation:
                if qtype == dns.rdatatype.DS and dns.rdatatype.DS not in types:
                    return NegativeProof(
                        NegativeProofStatus.VALID,
                        f"no DS exists at the delegation {qname}",
                        (rrset,),
                    )
                return NegativeProof(
                    NegativeProofStatus.INSUFFICIENT,
                    f"the NSEC at the delegation {qname} only proves DS absence",
                    (rrset,),
                )
            if qtype in types:
                return NegativeProof(
                    NegativeProofStatus.INSUFFICIENT,
                    f"the qtype is present in the NSEC bitmap at {qname}",
                    (rrset,),
                )
            if qtype != dns.rdatatype.CNAME and dns.rdatatype.CNAME in types:
                return NegativeProof(
                    NegativeProofStatus.INSUFFICIENT,
                    f"a CNAME is present in the NSEC bitmap at {qname}",
                    (rrset,),
                )
            return NegativeProof(
                NegativeProofStatus.VALID,
                f"no {dns.rdatatype.to_text(qtype)} exists at {qname}",
                (rrset,),
            )

    # Wildcard NODATA: the qname must not exist, and a matching wildcard
    # must exist without the qtype or a CNAME.
    for rrset in nsecs:
        if not rrset.name.is_wild() or not _wildcard_matches(rrset.name, qname):
            continue
        types = _nsec_types(_nsec_rdata(rrset))
        if qtype in types or dns.rdatatype.CNAME in types:
            continue
        covering = [
            other
            for other in nsecs
            if _covers(other.name, _nsec_rdata(other).next, qname)
        ]
        if covering:
            if covering[0] is rrset:
                used = (rrset,)
            else:
                used = (covering[0], rrset)
            return NegativeProof(
                NegativeProofStatus.VALID,
                f"no {dns.rdatatype.to_text(qtype)} exists at the wildcard "
                f"{rrset.name} matching {qname}",
                used,
            )
    return NegativeProof(
        NegativeProofStatus.INSUFFICIENT,
        f"no NSEC proves the absence of {dns.rdatatype.to_text(qtype)} at {qname}",
        tuple(nsecs),
    )


def validate_negative_response(
    question: dns.message.Message | tuple[dns.name.Name, dns.rdatatype.RdataType | int],
    response: dns.message.Message,
    keys: dict[dns.name.Name, dns.rdataset.Rdataset | dns.node.Node],
    now: float | None = None,
    policy: dns.dnssec.Policy | None = None,
) -> NegativeProof:
    """Offline validation of a negative (NXDOMAIN or NODATA) response.

    The relevant NSEC RRsets in the response's authority section are
    first validated against the trusted zone DNSKEYs, and the NSEC proof
    is then evaluated per RFC 4035 section 5.4 with the applicable RFC
    6840 clarifications.  Only plain NSEC is supported; NSEC3 and
    building a chain of trust from the root are out of scope.

    :param question: The question, either a query
        :py:class:`dns.message.Message` with a single question, or a
        (``dns.name.Name``, rdtype) tuple.
    :param response: The response message to validate.
    :type response: :py:class:`dns.message.Message`
    :param keys: The trusted key dictionary for the zone, keyed by
        :py:class:`dns.name.Name`, with :py:class:`dns.node.Node` or
        :py:class:`dns.rdataset.Rdataset` values, as for
        :py:func:`dns.dnssec.validate`.
    :param now: The validation time in seconds since the epoch.  If
        ``None``, the actual current time is used.
    :type now: float or ``None``
    :param policy: The signature validation policy to use.  If ``None``,
        ``dns.dnssec.default_policy`` is used.
    :type policy: :py:class:`dns.dnssec.Policy` or ``None``
    :returns: The validation outcome.
    :rtype: :py:class:`NegativeProof`
    """
    if isinstance(question, dns.message.Message):
        if len(question.question) != 1:
            raise ValueError("the question message must have exactly one question")
        qname = question.question[0].name
        qtype = question.question[0].rdtype
    else:
        qname, qtype = question
        qtype = dns.rdatatype.RdataType.make(qtype)
    qname = qname.derelativize(dns.name.root)

    if now is None:
        now = time.time()

    trusted = {name.derelativize(dns.name.root) for name in keys}

    # Find the innermost trusted zone containing the qname.  NSECs from
    # any other zone cannot prove anything about this qname, even if
    # their signatures are valid for their own zone.
    zone = None
    for name in trusted:
        if qname.is_subdomain(name) and (zone is None or len(name) > len(zone)):
            zone = name
    if zone is None:
        return NegativeProof(
            NegativeProofStatus.INSUFFICIENT,
            f"the qname {qname} is not in any trusted zone",
            (),
        )

    nsec_rrsets = {}
    rrsig_rrsets = {}
    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NSEC:
            nsec_rrsets[rrset.name] = rrset
        elif rrset.rdtype == dns.rdatatype.RRSIG and rrset.covers == dns.rdatatype.NSEC:
            rrsig_rrsets[rrset.name] = rrset

    # Validate the NSEC RRsets.  RRsets without signatures, or signed
    # only by zones we do not trust, are unusable and ignored.
    validated = []
    for owner, rrset in nsec_rrsets.items():
        rrsigset = rrsig_rrsets.get(owner)
        if rrsigset is None:
            continue
        if not any(
            isinstance(rrsig, RRSIG) and rrsig.signer in trusted for rrsig in rrsigset
        ):
            continue
        try:
            dns.dnssec.validate(rrset, rrsigset, keys, now=now, policy=policy)
        except (ValidationFailure, UnsupportedAlgorithm) as e:
            return NegativeProof(
                NegativeProofStatus.VALIDATION_FAILED,
                f"NSEC RRset at {owner} failed validation: {e}",
                (),
            )
        if owner.is_subdomain(zone):
            validated.append(rrset)

    if not validated:
        return NegativeProof(
            NegativeProofStatus.INSUFFICIENT,
            f"no validated NSEC RRsets for zone {zone}",
            (),
        )

    rcode = response.rcode()
    if rcode == dns.rcode.NXDOMAIN:
        return _prove_nxdomain(qname, zone, validated)
    elif rcode == dns.rcode.NOERROR:
        return _prove_nodata(qname, qtype, zone, validated)
    else:
        return NegativeProof(
            NegativeProofStatus.INSUFFICIENT,
            f"rcode {dns.rcode.to_text(rcode)} is not a negative response",
            tuple(validated),
        )
