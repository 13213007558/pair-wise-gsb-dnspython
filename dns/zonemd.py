# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""ZONEMD (RFC 8976) zone digest computation and verification.

This module is a complete entry point for authoritative servers that
want to generate a ZONEMD RR when publishing a zone, and for receivers
that want to verify the digest of a zone loaded from a remote source.
It handles scheme and hash algorithm selection, serial selection, the
RFC 8976 exclusion rules (the apex ZONEMD RRset and any RRSIGs covering
it are not digested), and pre-publication checks.
"""

import dataclasses
from collections.abc import Iterable

import dns.enum
import dns.name
import dns.rdatatype
import dns.rdtypes.ANY.ZONEMD
import dns.rrset
import dns.zone
from dns.zonetypes import DigestHashAlgorithm, DigestScheme, _digest_hashers


class ZonemdDiagnostic(dns.enum.IntEnum):
    """ZONEMD verification diagnostic."""

    OK = 0
    """The ZONEMD record verified successfully."""

    NO_ORIGIN = 1
    """The zone has no origin, so it cannot be verified."""

    NO_SOA = 2
    """The zone has no SOA record at its origin."""

    NO_ZONEMD = 3
    """The zone has no ZONEMD RRset at its origin."""

    SERIAL_MISMATCH = 4
    """The ZONEMD serial does not match the zone's SOA serial."""

    UNSUPPORTED_SCHEME = 5
    """The ZONEMD scheme is not supported."""

    UNSUPPORTED_HASH_ALGORITHM = 6
    """The ZONEMD hash algorithm is not supported."""

    DIGEST_MISMATCH = 7
    """The ZONEMD digest does not match the computed digest."""

    BUDGET_EXCEEDED = 8
    """The digest computation exceeded its size budget."""


@dataclasses.dataclass(frozen=True)
class ZonemdStatus:
    """The outcome of verifying a single ZONEMD record.

    ``zonemd`` is the ZONEMD rdata that was verified, or ``None`` if
    verification could not be associated with a particular record (e.g.
    the zone has no origin, or no ZONEMD RRset at its origin).

    ``diagnostic`` is a :py:class:`dns.zonemd.ZonemdDiagnostic`.
    """

    zonemd: dns.rdtypes.ANY.ZONEMD.ZONEMD | None
    diagnostic: ZonemdDiagnostic

    @property
    def ok(self) -> bool:
        """``True`` if the record verified successfully."""
        return self.diagnostic == ZonemdDiagnostic.OK


def _origin_name(zone: dns.zone.Zone) -> dns.name.Name:
    if zone.relativize:
        return dns.name.empty
    assert zone.origin is not None
    return zone.origin


def compute_zonemd(
    zone: dns.zone.Zone,
    hash_algorithm: DigestHashAlgorithm | int = DigestHashAlgorithm.SHA384,
    scheme: DigestScheme | int = DigestScheme.SIMPLE,
    serial: int | None = None,
    *,
    ttl: int | None = None,
    attach: bool = False,
    size_limit: int | None = None,
) -> dns.rdtypes.ANY.ZONEMD.ZONEMD:
    """Compute a ZONEMD digest for *zone*, as a publisher would when
    generating the zone for publication.

    The zone is digested in canonical form: owners, types, classes, and
    rdatas are sorted as specified in RFC 8976, and the apex ZONEMD
    RRset (and any RRSIGs covering it) are excluded.  The zone is not
    modified unless *attach* is ``True``.

    :param zone: The zone to digest.
    :type zone: :py:class:`dns.zone.Zone`
    :param hash_algorithm: The ZONEMD hash algorithm to use; the default
        is :py:attr:`dns.zonetypes.DigestHashAlgorithm.SHA384`.
    :type hash_algorithm: :py:class:`dns.zonetypes.DigestHashAlgorithm` or int
    :param scheme: The ZONEMD scheme to use; the default is
        :py:attr:`dns.zonetypes.DigestScheme.SIMPLE`.
    :type scheme: :py:class:`dns.zonetypes.DigestScheme` or int
    :param serial: The serial to place in the ZONEMD record.  If
        ``None`` (the default), the zone's SOA serial is used.
    :type serial: int or None
    :param ttl: The TTL to use for the ZONEMD RRset if *attach* is
        ``True``.  If ``None`` (the default), the TTL of the zone's SOA
        RRset is used.
    :type ttl: int or None
    :param bool attach: If ``True``, attach the computed digest to the
        zone as a new ZONEMD RRset at the origin, replacing any existing
        ZONEMD RRset.  If ``False`` (the default), the zone is not
        modified.
    :param size_limit: If not ``None``, the maximum number of bytes of
        canonical zone data that may be digested.  If the limit would be
        exceeded, :py:exc:`dns.zone.DigestBudgetExceeded` is raised and
        no (partial) digest is returned.  This allows large zones to be
        processed in a streaming fashion with a bounded budget.
    :type size_limit: int or None
    :raises dns.zone.UnknownOrigin: if the zone has no origin.
    :raises dns.zone.NoSOA: if the zone has no SOA record and *serial*
        (or the SOA TTL for *attach*) is needed.
    :raises dns.zone.UnsupportedDigestScheme: if *scheme* is not
        supported.
    :raises dns.zone.UnsupportedDigestHashAlgorithm: if *hash_algorithm*
        is not supported.
    :raises dns.zone.DigestBudgetExceeded: if *size_limit* is exceeded.
    :rtype: :py:class:`dns.rdtypes.ANY.ZONEMD.ZONEMD`
    """
    if zone.origin is None:
        raise dns.zone.UnknownOrigin
    hash_algorithm = DigestHashAlgorithm.make(hash_algorithm)
    scheme = DigestScheme.make(scheme)
    if serial is None:
        serial = zone.get_soa().serial
    digest = zone._compute_digest(hash_algorithm, scheme, size_limit)
    zonemd = dns.rdtypes.ANY.ZONEMD.ZONEMD(
        zone.rdclass, dns.rdatatype.ZONEMD, serial, scheme, hash_algorithm, digest
    )
    if attach:
        origin_name = _origin_name(zone)
        if ttl is None:
            soa_rds = zone.get_rdataset(origin_name, dns.rdatatype.SOA)
            if soa_rds is None:
                raise dns.zone.NoSOA
            ttl = soa_rds.ttl
        rrset = dns.rrset.RRset(origin_name, zone.rdclass, dns.rdatatype.ZONEMD)
        rrset.add(zonemd, ttl)
        zone.replace_rdataset(origin_name, rrset)
    return zonemd


def verify_zonemd(
    zone: dns.zone.Zone,
    zonemd: (
        dns.rdtypes.ANY.ZONEMD.ZONEMD | Iterable[dns.rdtypes.ANY.ZONEMD.ZONEMD] | None
    ) = None,
    *,
    size_limit: int | None = None,
) -> list[ZonemdStatus]:
    """Verify the ZONEMD records of a zone, e.g. after loading it from a
    remote source.

    Each ZONEMD record is verified individually, and a
    :py:class:`dns.zonemd.ZonemdStatus` is returned for each, with a
    diagnostic distinguishing serial mismatches, unsupported schemes or
    hash algorithms, a missing origin, and digest mismatches.  The
    returned list has one status per record checked; verification of the
    zone as a whole typically requires at least one status to be ``ok``.

    :param zone: The zone to verify.
    :type zone: :py:class:`dns.zone.Zone`
    :param zonemd: A specific ZONEMD rdata (or an iterable of them) to
        verify.  If ``None`` (the default), the ZONEMD RRset at the
        zone's origin is used.
    :param size_limit: If not ``None``, the maximum number of bytes of
        canonical zone data that may be digested; if exceeded, the
        record's diagnostic is
        :py:attr:`dns.zonemd.ZonemdDiagnostic.BUDGET_EXCEEDED`.
    :type size_limit: int or None
    :rtype: list of :py:class:`dns.zonemd.ZonemdStatus`
    """
    if zone.origin is None:
        return [ZonemdStatus(None, ZonemdDiagnostic.NO_ORIGIN)]
    digests: list[dns.rdtypes.ANY.ZONEMD.ZONEMD]
    if zonemd is None:
        rds = zone.get_rdataset(_origin_name(zone), dns.rdatatype.ZONEMD)
        if rds is None:
            return [ZonemdStatus(None, ZonemdDiagnostic.NO_ZONEMD)]
        digests = list(rds)
    elif isinstance(zonemd, dns.rdtypes.ANY.ZONEMD.ZONEMD):
        digests = [zonemd]
    else:
        digests = list(zonemd)
    try:
        serial = zone.get_soa().serial
    except dns.zone.NoSOA:
        return [ZonemdStatus(z, ZonemdDiagnostic.NO_SOA) for z in digests]
    statuses = []
    for z in digests:
        diagnostic: ZonemdDiagnostic
        if z.scheme != DigestScheme.SIMPLE:
            diagnostic = ZonemdDiagnostic.UNSUPPORTED_SCHEME
        elif z.hash_algorithm not in _digest_hashers:
            diagnostic = ZonemdDiagnostic.UNSUPPORTED_HASH_ALGORITHM
        elif z.serial != serial:
            diagnostic = ZonemdDiagnostic.SERIAL_MISMATCH
        else:
            try:
                computed = zone._compute_digest(z.hash_algorithm, z.scheme, size_limit)
            except dns.zone.DigestBudgetExceeded:
                diagnostic = ZonemdDiagnostic.BUDGET_EXCEEDED
            else:
                if computed == z.digest:
                    diagnostic = ZonemdDiagnostic.OK
                else:
                    diagnostic = ZonemdDiagnostic.DIGEST_MISMATCH
        statuses.append(ZonemdStatus(z, diagnostic))
    return statuses
