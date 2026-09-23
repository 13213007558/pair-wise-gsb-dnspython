# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""ZONEMD (RFC 8976) zone message digest computation and verification.

This module is a complete entry point for authoritative servers and zone
publishers that need to generate a ZONEMD RRset before publishing a zone,
or that need to verify the digest of a zone loaded from elsewhere, e.g.
after a zone transfer.  It handles scheme and hash algorithm selection,
canonical ordering of owners, types, classes, and rdatas, the exclusion of
the apex ZONEMD RRset (and any signatures over it), and pre-publication
checks such as SOA serial number agreement.
"""

import struct

import dns.exception
import dns.name
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.ZONEMD
import dns.rrset
import dns.zone
from dns.zonetypes import DigestHashAlgorithm, DigestScheme, _digest_hashers


class DigestSerialMismatch(dns.exception.DNSException):
    """The ZONEMD digest's serial number does not match the zone's SOA
    serial number."""


class DigestBudgetExceeded(dns.exception.DNSException):
    """The ZONEMD computation budget was exceeded."""


def _compute_digest(
    zone: "dns.zone.Zone",
    hash_algorithm: DigestHashAlgorithm,
    scheme: DigestScheme = DigestScheme.SIMPLE,
    budget: int | None = None,
) -> bytes:
    """Compute a zone's digest, streaming over its records.

    The zone is read incrementally and the digest is updated one RR at a
    time, so zones of any size may be processed.  *budget*, if not
    ``None``, is the maximum number of RRs to process; if the zone
    contains more RRs than the budget allows,
    :py:exc:`dns.zonemd.DigestBudgetExceeded` is raised and no partial
    digest is returned.
    """
    hashinfo = _digest_hashers.get(hash_algorithm)
    if not hashinfo:
        raise dns.zone.UnsupportedDigestHashAlgorithm
    if scheme != DigestScheme.SIMPLE:
        raise dns.zone.UnsupportedDigestScheme
    if zone.origin is None:
        raise dns.zone.UnknownOrigin
    if zone.relativize:
        origin_name = dns.name.empty
    else:
        origin_name = zone.origin
    hasher = hashinfo()
    records = 0
    for name, node in sorted(zone.items()):
        rrnamebuf = name.to_digestable(zone.origin)
        for rdataset in sorted(node, key=lambda rds: (rds.rdtype, rds.covers)):
            if name == origin_name and dns.rdatatype.ZONEMD in (
                rdataset.rdtype,
                rdataset.covers,
            ):
                # The apex ZONEMD RRset, and any signatures over it, do not
                # participate in the digest.
                continue
            rrfixed = struct.pack(
                "!HHI", rdataset.rdtype, rdataset.rdclass, rdataset.ttl
            )
            rdatas = sorted(rdata.to_digestable(zone.origin) for rdata in rdataset)
            for rdata in rdatas:
                records += 1
                if budget is not None and records > budget:
                    raise DigestBudgetExceeded
                rrlen = struct.pack("!H", len(rdata))
                hasher.update(rrnamebuf + rrfixed + rrlen + rdata)
    return hasher.digest()


def _default_zonemd_ttl(zone: "dns.zone.Zone") -> int:
    # Prefer the TTL of an existing apex ZONEMD RRset, then the SOA TTL.
    assert zone.origin is not None
    zonemd = zone.get_rdataset(zone.origin, dns.rdatatype.ZONEMD)
    if zonemd is not None:
        return zonemd.ttl
    soa = zone.get_rdataset(zone.origin, dns.rdatatype.SOA)
    if soa is not None:
        return soa.ttl
    return 0


def compute_zonemd(
    zone: "dns.zone.Zone",
    hash_algorithm: DigestHashAlgorithm | int = DigestHashAlgorithm.SHA384,
    scheme: DigestScheme | int = DigestScheme.SIMPLE,
    serial: int | None = None,
    ttl: int | None = None,
    budget: int | None = None,
    attach: bool = False,
) -> dns.rrset.RRset:
    """Compute the ZONEMD RRset for a zone.

    *zone* is the :py:class:`dns.zone.Zone` to digest.  The zone is not
    modified unless *attach* is ``True``.

    *hash_algorithm* is the ZONEMD hash algorithm to use; the default is
    SHA384.  *scheme* is the ZONEMD scheme; the default (and only
    currently standardized value) is SIMPLE.

    *serial* is the serial number to place in the ZONEMD rdata; if
    ``None``, the zone's SOA serial number is used.

    *ttl* is the TTL for the returned RRset; if ``None``, the TTL of an
    existing apex ZONEMD RRset is used, falling back to the SOA TTL.

    *budget*, if not ``None``, is the maximum number of RRs to process
    while digesting; exceeding it raises
    :py:exc:`dns.zonemd.DigestBudgetExceeded` instead of returning a
    partial digest.

    If *attach* is ``True``, the computed RRset replaces any ZONEMD RRset
    at the zone's origin, allowing a publisher to generate and attach the
    digest in one step.

    Returns the computed ZONEMD :py:class:`dns.rrset.RRset`, owned by the
    zone's origin.

    :raises dns.zone.UnknownOrigin: if the zone has no origin.
    :raises dns.zone.NoSOA: if *serial* is ``None`` and the zone has no
        SOA record.
    :raises dns.zone.UnsupportedDigestScheme: if *scheme* is not
        supported.
    :raises dns.zone.UnsupportedDigestHashAlgorithm: if *hash_algorithm*
        is not supported.
    :raises dns.zonemd.DigestBudgetExceeded: if *budget* is exceeded.
    """
    scheme = DigestScheme.make(scheme)
    hash_algorithm = DigestHashAlgorithm.make(hash_algorithm)
    if zone.origin is None:
        raise dns.zone.UnknownOrigin
    if serial is None:
        serial = zone.get_soa().serial
    digest = _compute_digest(zone, hash_algorithm, scheme, budget)
    zonemd = dns.rdtypes.ANY.ZONEMD.ZONEMD(
        zone.rdclass, dns.rdatatype.ZONEMD, serial, scheme, hash_algorithm, digest
    )
    if ttl is None:
        ttl = _default_zonemd_ttl(zone)
    rrset = dns.rrset.RRset(zone.origin, zone.rdclass, dns.rdatatype.ZONEMD)
    rrset.add(zonemd, ttl)
    if attach:
        zone.replace_rdataset(zone.origin, rrset)
    return rrset


def verify_zonemd(
    zone: "dns.zone.Zone",
    zonemd: dns.rdtypes.ANY.ZONEMD.ZONEMD | dns.rdataset.Rdataset | None = None,
    budget: int | None = None,
) -> None:
    """Verify a zone's ZONEMD digest.

    *zone* is the :py:class:`dns.zone.Zone` to verify.  *zonemd* is a
    ZONEMD rdata, an rdataset of ZONEMD rdatas, or ``None``, in which
    case the ZONEMD RRset at the zone's origin is used.

    Each ZONEMD record is checked in turn: its scheme and hash algorithm
    must be supported, its serial number must match the zone's SOA serial
    number, and its digest must match the computed zone digest.  The
    verification succeeds if at least one record verifies.  If no record
    verifies, the diagnostic for the first failing record is raised.

    *budget*, if not ``None``, is the maximum number of RRs to process
    while digesting; exceeding it raises
    :py:exc:`dns.zonemd.DigestBudgetExceeded` instead of comparing a
    partial digest.

    :raises dns.zone.UnknownOrigin: if the zone has no origin.
    :raises dns.zone.NoDigest: if *zonemd* is ``None`` and the zone has
        no ZONEMD RRset at its origin.
    :raises dns.zone.NoSOA: if the zone has no SOA record.
    :raises dns.zone.UnsupportedDigestScheme: if the scheme of a ZONEMD
        record is not supported.
    :raises dns.zone.UnsupportedDigestHashAlgorithm: if the hash
        algorithm of a ZONEMD record is not supported.
    :raises dns.zonemd.DigestSerialMismatch: if a ZONEMD record's serial
        number does not match the zone's SOA serial number.
    :raises dns.zone.DigestVerificationFailure: if no ZONEMD record's
        digest matches the computed zone digest.
    :raises dns.zonemd.DigestBudgetExceeded: if *budget* is exceeded.
    """
    if zone.origin is None:
        raise dns.zone.UnknownOrigin
    digests: dns.rdataset.Rdataset | list[dns.rdtypes.ANY.ZONEMD.ZONEMD]
    if zonemd is None:
        rds = zone.get_rdataset(zone.origin, dns.rdatatype.ZONEMD)
        if rds is None:
            raise dns.zone.NoDigest
        digests = rds
    elif isinstance(zonemd, dns.rdataset.Rdataset):
        digests = zonemd
    else:
        digests = [zonemd]
    serial = zone.get_soa().serial
    failure: dns.exception.DNSException | None = None
    for digest in digests:
        if digest.scheme != DigestScheme.SIMPLE:
            failure = failure or dns.zone.UnsupportedDigestScheme()
            continue
        if digest.hash_algorithm not in _digest_hashers:
            failure = failure or dns.zone.UnsupportedDigestHashAlgorithm()
            continue
        if digest.serial != serial:
            failure = failure or DigestSerialMismatch()
            continue
        computed = _compute_digest(zone, digest.hash_algorithm, digest.scheme, budget)
        if computed == digest.digest:
            return
        failure = failure or dns.zone.DigestVerificationFailure()
    if failure is not None:
        raise failure
    raise dns.zone.DigestVerificationFailure
