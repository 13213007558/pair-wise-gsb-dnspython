# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Three-way merging of DNS zones.

This module implements a merge(base, ours, theirs) style merge for
:py:class:`dns.zone.Zone` objects, as is needed when two automation
branches have independently modified the same zone and a textual
line-based merge would silently hide TTL or CNAME conflicts.

The identity of an RRset is its normalized owner name, class, type, and
covers; its value is the TTL plus the normalized set of rdata.  If only
one side changed a value, that side wins.  If both sides made the same
change, the change is accepted.  If both sides changed the same RRset in
different ways, or one side deleted an RRset the other side modified, a
conflict is reported; rdata sets are never silently unioned.  Name case,
relative/absolute spelling, and rdata ordering do not create false
conflicts.

After the per-RRset merge, whole-zone invariants are checked: a CNAME
may not coexist with other data at a name (even if the two sides added
the incompatible types independently), and the zone apex must have SOA
and NS rdatasets.  The SOA serial of the merged zone is computed by a
caller-supplied policy and validated with RFC 1982 serial number
arithmetic; it is never simply the numeric maximum of the inputs.

None of the three input zones is modified.

Example:

.. code-block:: python

    import dns.zone
    import dns.zonemerge

    base = dns.zone.from_file("zone.db.base", "example.com")
    ours = dns.zone.from_file("zone.db.ours", "example.com")
    theirs = dns.zone.from_file("zone.db.theirs", "example.com")

    result = dns.zonemerge.merge_zones(base, ours, theirs)
    if result.ok:
        result.zone.to_file("zone.db.merged")
    else:
        for conflict in result.conflicts:
            print(conflict)
"""

import dataclasses
import enum
from typing import Callable, cast

import dns.exception
import dns.name
import dns.node
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.serial
import dns.zone


class BadSerial(dns.exception.DNSException):
    """A serial number policy produced an invalid serial number."""


class IncompatibleZones(dns.exception.DNSException):
    """The zones being merged do not have the same origin and class."""


class ConflictReason(enum.Enum):
    """The reason a merge conflict occurred."""

    #: Both sides changed the same RRset in different ways.
    BOTH_MODIFIED = "both-modified"
    #: One side deleted an RRset that the other side modified.
    DELETE_VS_MODIFY = "delete-vs-modify"
    #: The merge would place a CNAME and other data at the same name.
    CNAME_AND_OTHER_DATA = "cname-and-other-data"
    #: The merged zone has no SOA rdataset at the origin.
    MISSING_SOA = "missing-soa"
    #: The merged zone has no NS rdataset at the origin.
    MISSING_NS = "missing-ns"


@dataclasses.dataclass(frozen=True)
class RrsetKey:
    """The normalized identity of an RRset in a zone merge.

    The *owner* is always an absolute name.
    """

    owner: dns.name.Name
    rdclass: dns.rdataclass.RdataClass
    rdtype: dns.rdatatype.RdataType
    covers: dns.rdatatype.RdataType

    def __str__(self) -> str:
        ctext = ""
        if self.covers != dns.rdatatype.NONE:
            ctext = "(" + dns.rdatatype.to_text(self.covers) + ")"
        return (
            f"{self.owner.to_text()} {dns.rdataclass.to_text(self.rdclass)} "
            f"{dns.rdatatype.to_text(self.rdtype)}{ctext}"
        )


@dataclasses.dataclass(frozen=True)
class Conflict:
    """A single merge conflict.

    *base*, *ours*, and *theirs* are the rdatasets for the conflicted
    RRset in each of the three input zones, or ``None`` where the RRset
    is absent.  They reference the input zones' rdatasets and must not
    be mutated.
    """

    key: RrsetKey
    reason: ConflictReason
    base: dns.rdataset.Rdataset | None
    ours: dns.rdataset.Rdataset | None
    theirs: dns.rdataset.Rdataset | None

    def __str__(self) -> str:
        def fmt(rds: dns.rdataset.Rdataset | None) -> str:
            if rds is None:
                return "<absent>"
            return rds.to_text()

        return (
            f"{self.key}: {self.reason.value}\n"
            f"    base:   {fmt(self.base)}\n"
            f"    ours:   {fmt(self.ours)}\n"
            f"    theirs: {fmt(self.theirs)}"
        )


@dataclasses.dataclass
class MergeResult:
    """The result of a three-way zone merge.

    If the merge succeeded, *zone* is the merged zone and *conflicts* is
    empty.  If the merge failed, *zone* is ``None`` and *conflicts*
    describes every conflict, in a stable order.
    """

    zone: dns.zone.Zone | None
    conflicts: list[Conflict]

    @property
    def ok(self) -> bool:
        """Did the merge succeed?"""
        return self.zone is not None


#: A serial number policy computes the SOA serial of the merged zone
#: from the base, ours, and theirs serials.  The result must be greater
#: than the base serial in RFC 1982 serial number arithmetic.
SerialPolicy = Callable[[int, int, int], int]


def increment_serial_policy(base: int, ours: int, theirs: int) -> int:
    """A serial policy returning the base serial incremented by one,
    using RFC 1982 serial number arithmetic."""
    return (dns.serial.Serial(base) + 1).value


def _fixed_serial_policy(serial: int) -> SerialPolicy:
    def policy(base: int, ours: int, theirs: int) -> int:
        return serial

    return policy


def _soa_serial(rdataset: dns.rdataset.Rdataset) -> int:
    return cast(dns.rdtypes.ANY.SOA.SOA, rdataset[0]).serial


def _value(
    rdataset: dns.rdataset.Rdataset | None, origin: dns.name.Name
) -> tuple[int, frozenset[bytes]] | None:
    """The normalized value of an rdataset: its TTL and the set of its
    rdata in DNSSEC canonical form, with relative names made absolute
    against the zone origin."""
    if rdataset is None:
        return None
    return (
        rdataset.ttl,
        frozenset(rd.to_digestable(origin) for rd in rdataset),
    )


def _zone_map(zone: dns.zone.Zone) -> dict[RrsetKey, dns.rdataset.Rdataset]:
    assert zone.origin is not None
    result = {}
    for name, node in zone.nodes.items():
        owner = name.derelativize(zone.origin)
        for rds in node.rdatasets:
            if len(rds) == 0:
                continue
            key = RrsetKey(owner, rds.rdclass, rds.rdtype, rds.covers)
            result[key] = rds
    return result


def _key_order(key: RrsetKey) -> tuple:
    return (
        key.owner.canonicalize(),
        int(key.rdclass),
        int(key.rdtype),
        int(key.covers),
    )


def _copy_rdataset(
    rdataset: dns.rdataset.Rdataset, origin: dns.name.Name
) -> dns.rdataset.Rdataset:
    # Copy so that the merged zone shares no mutable state with the
    # inputs.  Rdata are immutable and are shared.  Sorting the rdata
    # makes the merged zone's text output deterministic.
    new = dns.rdataset.Rdataset(rdataset.rdclass, rdataset.rdtype, rdataset.covers)
    new.update_ttl(rdataset.ttl)
    for rd in sorted(rdataset, key=lambda rd: rd.to_digestable(origin)):
        new.add(rd)
    return new


def merge_zones(
    base: dns.zone.Zone,
    ours: dns.zone.Zone,
    theirs: dns.zone.Zone,
    *,
    serial_policy: SerialPolicy | int | None = None,
) -> MergeResult:
    """Merge three versions of a zone.

    *base* is the common ancestor of *ours* and *theirs*.  All three
    zones must have the same origin and class.  The inputs are not
    modified.

    *serial_policy* determines the SOA serial of the merged zone.  It
    may be a callable ``(base_serial, ours_serial, theirs_serial) ->
    serial``, an ``int`` to use verbatim, or ``None``, in which case
    :py:func:`increment_serial_policy` is used.  The resulting serial
    must be greater than the base serial in RFC 1982 serial number
    arithmetic; otherwise :py:exc:`BadSerial` is raised.  The policy is
    only applied if the base zone has an SOA.

    :rtype: :py:class:`MergeResult`
    """
    if serial_policy is None:
        policy = increment_serial_policy
    elif isinstance(serial_policy, int):
        policy = _fixed_serial_policy(serial_policy)
    else:
        policy = serial_policy

    origin = base.origin
    if origin is None:
        raise IncompatibleZones("base zone has no origin")
    for zone in (ours, theirs):
        if zone.origin != origin or zone.rdclass != base.rdclass:
            raise IncompatibleZones("all zones must have the same origin and class")

    base_map = _zone_map(base)
    ours_map = _zone_map(ours)
    theirs_map = _zone_map(theirs)

    # Per-RRset three-way merge.
    merged: dict[RrsetKey, dns.rdataset.Rdataset] = {}
    conflicts: list[Conflict] = []
    keys = set(base_map) | set(ours_map) | set(theirs_map)
    for key in sorted(keys, key=_key_order):
        b = base_map.get(key)
        o = ours_map.get(key)
        t = theirs_map.get(key)
        bv = _value(b, origin)
        ov = _value(o, origin)
        tv = _value(t, origin)
        if ov == tv:
            # Both sides agree (including both-deleted and
            # both-changed-identically).
            chosen = o
        elif bv == ov:
            # Only theirs changed it.
            chosen = t
        elif bv == tv:
            # Only ours changed it.
            chosen = o
        else:
            if b is not None and (o is None) != (t is None):
                reason = ConflictReason.DELETE_VS_MODIFY
            else:
                reason = ConflictReason.BOTH_MODIFIED
            conflicts.append(Conflict(key, reason, b, o, t))
            continue
        if chosen is not None:
            merged[key] = chosen

    if conflicts:
        return MergeResult(None, conflicts)

    # Apply the serial policy to the merged SOA, if there is one to
    # validate against.
    soa_key = RrsetKey(origin, base.rdclass, dns.rdatatype.SOA, dns.rdatatype.NONE)
    base_soa = base_map.get(soa_key)
    if base_soa is not None:
        base_serial = _soa_serial(base_soa)
        ours_soa = ours_map.get(soa_key)
        theirs_soa = theirs_map.get(soa_key)
        ours_serial = _soa_serial(ours_soa) if ours_soa is not None else base_serial
        theirs_serial = _soa_serial(theirs_soa) if theirs_soa is not None else base_serial
        new_serial = policy(base_serial, ours_serial, theirs_serial)
        if not dns.serial.Serial(new_serial) > dns.serial.Serial(base_serial):
            raise BadSerial(
                f"serial policy produced {new_serial}, which is not greater "
                f"than the base serial {base_serial} in RFC 1982 arithmetic"
            )
        merged_soa = merged.get(soa_key)
        if merged_soa is not None:
            new_soa = merged_soa[0].replace(serial=new_serial)
            replacement = dns.rdataset.Rdataset(
                merged_soa.rdclass, merged_soa.rdtype, merged_soa.covers
            )
            replacement.update_ttl(merged_soa.ttl)
            replacement.add(new_soa)
            merged[soa_key] = replacement

    # Whole-zone checks: CNAME and other data may not coexist at a name.
    by_owner: dict[dns.name.Name, list[dns.rdataset.Rdataset]] = {}
    for key in sorted(merged, key=_key_order):
        by_owner.setdefault(key.owner, []).append(merged[key])
    for owner in sorted(by_owner, key=lambda n: n.canonicalize()):
        rdatasets = by_owner[owner]
        kinds = {dns.node.NodeKind.classify_rdataset(rds) for rds in rdatasets}
        if dns.node.NodeKind.CNAME in kinds and dns.node.NodeKind.REGULAR in kinds:
            incompatible = [
                rds
                for rds in rdatasets
                if dns.node.NodeKind.classify_rdataset(rds) != dns.node.NodeKind.NEUTRAL
            ]
            changed = [
                rds
                for rds in incompatible
                if _value(
                    base_map.get(RrsetKey(owner, rds.rdclass, rds.rdtype, rds.covers)),
                    origin,
                )
                != _value(rds, origin)
            ]
            for rds in changed or incompatible:
                key = RrsetKey(owner, rds.rdclass, rds.rdtype, rds.covers)
                conflicts.append(
                    Conflict(
                        key,
                        ConflictReason.CNAME_AND_OTHER_DATA,
                        base_map.get(key),
                        ours_map.get(key),
                        theirs_map.get(key),
                    )
                )

    # The apex must have SOA and NS.
    for rdtype, reason in (
        (dns.rdatatype.SOA, ConflictReason.MISSING_SOA),
        (dns.rdatatype.NS, ConflictReason.MISSING_NS),
    ):
        key = RrsetKey(origin, base.rdclass, rdtype, dns.rdatatype.NONE)
        if key not in merged:
            conflicts.append(
                Conflict(
                    key,
                    reason,
                    base_map.get(key),
                    ours_map.get(key),
                    theirs_map.get(key),
                )
            )

    if conflicts:
        return MergeResult(None, conflicts)

    # Build the merged zone.  Rdatasets are appended directly to the
    # nodes, bypassing the node's CNAME/other-data enforcement, as the
    # checks above have already validated the combination.
    zone = dns.zone.Zone(origin, base.rdclass)
    for owner in sorted(by_owner, key=lambda n: n.canonicalize()):
        node = dns.node.Node()
        for rds in by_owner[owner]:
            node.rdatasets.append(_copy_rdataset(rds, origin))
        zone.nodes[owner.relativize(origin)] = node
    return MergeResult(zone, [])
