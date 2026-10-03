# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Three-way merging of DNS zones.

This module provides a ``git``-style three-way merge for
:py:class:`dns.zone.Zone` objects.  Given a *base* zone and two derived
zones *ours* and *theirs*, :py:func:`dns.zonemerge.merge` either returns a
new zone containing the merged changes, or raises
:py:class:`dns.zonemerge.MergeConflicts`, which lists every conflict that
prevented an automatic merge.  :py:func:`dns.zonemerge.try_merge` does the
same thing but returns a :py:class:`dns.zonemerge.MergeResult` instead of
raising.

The merge unit is an RRset, identified by its owner name, class, type, and
covers value.  A unit's value is its TTL together with the set of its
normalized rdatas.  If only one side changed a unit the change is accepted;
if both sides changed it to the same value that is also accepted.  If the
two sides made different changes, or one side deleted a unit the other
side modified, a conflict is reported; rdata sets are never silently
unioned together.

Owner-name case, relative versus absolute name spelling, and record
ordering are normalized before comparison and therefore do not cause
spurious conflicts.

After the units have been merged the result is checked against
zone-wide constraints: a node may not have both a CNAME and other data,
and the origin must have a valid SOA and NS RRset.  The SOA serial is
updated by a caller-supplied policy and validated using DNS serial
number arithmetic (RFC 1982); it is never simply the numerically larger
value.

None of the three input zones are modified; the merged zone is a freshly
built object.

For example, if *ours* adds an ``A`` record for ``host-a`` and *theirs*
adds one for ``host-b``::

    merged = dns.zonemerge.merge(base, ours, theirs)

The merged zone contains both hosts.  If both sides changed the TTL of
the same RRset to different values::

    try:
        merged = dns.zonemerge.merge(base, ours, theirs)
    except dns.zonemerge.MergeConflicts as e:
        for conflict in e.conflicts:
            print(conflict)

The caller resolves the conflict, and the merge can be retried.
"""

import dataclasses
import enum
from collections.abc import Callable
from typing import NamedTuple

import dns.exception
import dns.name
import dns.node
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.serial
import dns.zone


class MergeError(dns.exception.DNSException):
    """The merge request itself is invalid, e.g. the zones have different
    origins or rdata classes.
    """


class ConflictReason(enum.Enum):
    """The reason a :py:class:`MergeConflict` was reported.

    * :py:attr:`CONFLICTING_CHANGES`: both sides changed the same merge
      unit but to different values.
    * :py:attr:`DELETE_MODIFY`: one side deleted a merge unit while the
      other side modified it.
    * :py:attr:`CNAME_AND_OTHER_DATA`: a node in the merged zone has both
      a CNAME RRset and another RRset which is not permitted next to a
      CNAME (only RRSIG/SIG covering the CNAME and NSEC are allowed).
    * :py:attr:`NO_SOA`: the origin of the merged zone has no SOA
      RRset.
    * :py:attr:`INVALID_SOA`: the origin of the merged zone has an
      invalid SOA RRset, e.g. more than one SOA rdata.
    * :py:attr:`NO_NS`: the origin of the merged zone has no NS RRset.
    * :py:attr:`INVALID_SERIAL`: the serial chosen by the serial policy
      is not valid according to DNS serial number arithmetic; it is not
      greater than or equal to a serial found in one of the branches.
    """

    CONFLICTING_CHANGES = "both sides changed the value differently"
    DELETE_MODIFY = "one side deleted the unit, the other side modified it"
    CNAME_AND_OTHER_DATA = "a CNAME cannot coexist with other data at the same name"
    NO_SOA = "the zone origin has no SOA RRset"
    INVALID_SOA = "the zone origin SOA RRset is invalid"
    NO_NS = "the zone origin has no NS RRset"
    INVALID_SERIAL = "the chosen SOA serial is invalid under RFC 1982 serial arithmetic"


@dataclasses.dataclass(frozen=True)
class MergeConflict:
    """A single merge conflict.

    :ivar reason: Why the conflict was reported.
    :vartype reason: :py:class:`ConflictReason`
    :ivar name: The absolute, DNSSEC canonical owner name of the unit the
        conflict is about; this is the zone origin for origin-level
        conflicts.
    :vartype name: :py:class:`dns.name.Name`
    :ivar rdtype: The rdata type of the unit the conflict is about; this
        is :py:attr:`dns.rdatatype.NONE` for origin-level conflicts that
        are not about a specific type.
    :vartype rdtype: :py:class:`dns.rdatatype.RdataType`
    :ivar covers: The covered type of the unit, or
        :py:attr:`dns.rdatatype.NONE`.
    :vartype covers: :py:class:`dns.rdatatype.RdataType`
    :ivar base: The value of the unit in the base zone, or ``None`` if
        the unit did not exist there.
    :vartype base: :py:class:`dns.rrset.RRset` or None
    :ivar ours: The value of the unit in the ours zone, or ``None`` if
        the unit did not exist there.
    :vartype ours: :py:class:`dns.rrset.RRset` or None
    :ivar theirs: The value of the unit in the theirs zone, or ``None"
        if the unit did not exist there.
    :vartype theirs: :py:class:`dns.rrset.RRset` or None
    :ivar detail: Additional human-readable information about the
        conflict, or ``None``.
    :vartype detail: str or None
    """

    reason: ConflictReason
    name: dns.name.Name
    rdtype: dns.rdatatype.RdataType = dns.rdatatype.NONE
    covers: dns.rdatatype.RdataType = dns.rdatatype.NONE
    base: dns.rrset.RRset | None = None
    ours: dns.rrset.RRset | None = None
    theirs: dns.rrset.RRset | None = None
    detail: str | None = None

    def __str__(self) -> str:
        parts = [f"{self.name} {self.reason.value}"]
        if self.detail is not None:
            parts.append(f"({self.detail})")
        return " ".join(parts)


@dataclasses.dataclass(frozen=True)
class MergeResult:
    """The result of a three-way merge.

    Exactly one of *merged* and *conflicts* is non-empty.  If there are
    no conflicts, *merged* is the new merged zone; otherwise *conflicts*
    is a list, in stable order, of all the conflicts found.

    :ivar merged: The merged zone, or ``None`` if there were conflicts.
    :vartype merged: :py:class:`dns.zone.Zone` or None
    :ivar conflicts: The conflicts found, in stable order.
    :vartype conflicts: tuple of :py:class:`MergeConflict`
    """

    merged: dns.zone.Zone | None
    conflicts: tuple[MergeConflict, ...] = ()

    def raise_if_conflicts(self) -> dns.zone.Zone:
        """Return the merged zone or raise :py:class:`MergeConflicts`.

        :rtype: :py:class:`dns.zone.Zone`
        :raises dns.zonemerge.MergeConflicts: if the merge had conflicts.
        """

        if self.merged is None:
            raise MergeConflicts(self.conflicts)
        return self.merged


class MergeConflicts(dns.exception.DNSException):
    """The three-way merge could not be completed automatically because
    there were conflicts.
    """

    def __init__(self, conflicts: tuple[MergeConflict, ...] | list[MergeConflict]):
        self.conflicts = tuple(conflicts)
        super().__init__(
            f"zone merge failed with {len(self.conflicts)} conflict(s)\n"
            + "\n".join(str(conflict) for conflict in self.conflicts)
        )


# A serial policy takes the serials found in the base, ours, and theirs
# SOA records (None if a side had no SOA) and returns the serial to use
# in the merged zone.  The chosen serial is then validated using DNS
# serial number arithmetic.
SerialPolicy = Callable[[int | None, int | None, int | None], int]


def _latest(a: int | None, b: int | None) -> int | None:
    """Return whichever of a and b is later in serial number arithmetic,
    treating None as absent.
    """

    if a is None:
        return b
    if b is None:
        return a
    sa = dns.serial.Serial(a)
    sb = dns.serial.Serial(b)
    if sb > sa:
        return b
    return a


def latest_serial(base: int | None, ours: int | None, theirs: int | None) -> int:
    """Serial policy: use the latest of the two branch serials.

    "Latest" is determined using RFC 1982 serial number arithmetic, not
    ordinary integer comparison.  If neither branch has an SOA serial,
    the base serial (which must exist in that case) is returned.
    """

    latest = _latest(ours, theirs)
    if latest is None:
        if base is None:
            raise MergeError("no SOA serial is available")
        latest = base
    return latest


def ours_serial(base: int | None, ours: int | None, theirs: int | None) -> int:
    """Serial policy: always take the *ours* branch serial."""

    serial = ours if ours is not None else base
    if serial is None:
        raise MergeError("no SOA serial is available")
    return serial


def theirs_serial(base: int | None, ours: int | None, theirs: int | None) -> int:
    """Serial policy: always take the *theirs* branch serial."""

    serial = theirs if theirs is not None else base
    if serial is None:
        raise MergeError("no SOA serial is available")
    return serial


def increment_serial(base: int | None, ours: int | None, theirs: int | None) -> int:
    """Serial policy: take the latest branch serial and increment it by
    one using RFC 1982 serial number arithmetic.

    This is appropriate when callers make a change without touching the
    SOA serial and want the merge to allocate a fresh serial; it is safe
    near serial wrap-around.
    """

    latest = latest_serial(base, ours, theirs)
    latest = (dns.serial.Serial(latest) + 1).value
    if latest == 0:
        latest = 1
    return latest


class _UnitKey(NamedTuple):
    name: dns.name.Name
    rdtype: dns.rdatatype.RdataType
    covers: dns.rdatatype.RdataType


@dataclasses.dataclass
class _Unit:
    """An RRset snapshot in absolute, canonical owner-name space."""

    key: _UnitKey
    ttl: int
    rdatas: tuple[dns.rdata.Rdata, ...]
    rdclass: dns.rdataclass.RdataClass

    def signature(self, origin: dns.name.Name) -> tuple[int, tuple[bytes, ...]]:
        # RDATA canonical wire form is independent of owner-name case,
        # relative/absolute spelling, and source record ordering.
        digests = tuple(sorted(rdata.to_digestable(origin) for rdata in self.rdatas))
        return (self.ttl, digests)


def _canonical_name(name: dns.name.Name, origin: dns.name.Name) -> dns.name.Name:
    """Return the absolute, lowercased form of an owner name."""

    if not name.is_absolute():
        name = name.derelativize(origin)
    return name.canonicalize()


def _index_zone(zone: dns.zone.Zone, origin: dns.name.Name) -> dict[_UnitKey, _Unit]:
    units: dict[_UnitKey, _Unit] = {}
    for name, node in zone.items():
        owner = _canonical_name(name, origin)
        for rdataset in node:
            key = _UnitKey(owner, rdataset.rdtype, rdataset.covers)
            units[key] = _Unit(
                key=key,
                ttl=rdataset.ttl,
                rdatas=tuple(rdataset),
                rdclass=rdataset.rdclass,
            )
    return units


def _make_view(unit: _Unit | None) -> dns.rrset.RRset | None:
    """Build a standalone, owner-bearing RRset for a conflict report.

    Views use absolute owner names so that units originating in
    relativized and non-relativized zones are presented uniformly.
    """

    if unit is None:
        return None
    rrset = dns.rrset.RRset(
        unit.key.name, unit.rdclass, unit.key.rdtype, unit.key.covers
    )
    for rdata in unit.rdatas:
        rrset.add(rdata)
    rrset.ttl = unit.ttl
    return rrset


def _views(
    base: _Unit | None,
    ours: _Unit | None,
    theirs: _Unit | None,
) -> tuple[
    dns.rrset.RRset | None,
    dns.rrset.RRset | None,
    dns.rrset.RRset | None,
]:
    # Conflict views are always shown using absolute names so that values
    # from relativized and non-relativized input zones are comparable.
    return (_make_view(base), _make_view(ours), _make_view(theirs))


def _conflict(
    reason: ConflictReason,
    key: _UnitKey,
    base: _Unit | None,
    ours: _Unit | None,
    theirs: _Unit | None,
    origin: dns.name.Name,
    detail: str | None = None,
) -> MergeConflict:
    base_view, ours_view, theirs_view = _views(base, ours, theirs)
    return MergeConflict(
        reason=reason,
        name=key.name,
        rdtype=key.rdtype,
        covers=key.covers,
        base=base_view,
        ours=ours_view,
        theirs=theirs_view,
        detail=detail,
    )


def _merge_units(
    base_units: dict[_UnitKey, _Unit],
    ours_units: dict[_UnitKey, _Unit],
    theirs_units: dict[_UnitKey, _Unit],
    origin: dns.name.Name,
) -> tuple[dict[_UnitKey, _Unit], list[MergeConflict]]:
    merged: dict[_UnitKey, _Unit] = {}
    conflicts: list[MergeConflict] = []
    keys = sorted(set(base_units) | set(ours_units) | set(theirs_units))
    for key in keys:
        base = base_units.get(key)
        ours = ours_units.get(key)
        theirs = theirs_units.get(key)
        b_sig = base.signature(origin) if base is not None else None
        o_sig = ours.signature(origin) if ours is not None else None
        t_sig = theirs.signature(origin) if theirs is not None else None
        winner: _Unit | None = None
        reason: ConflictReason | None = None
        if o_sig == t_sig:
            # Both deleted, both unchanged, or both made the same change.
            winner = ours
        elif base is None:
            # The unit was created after the base; a single-sided add is
            # accepted, but two different adds are a conflict.
            if ours is None:
                winner = theirs
            elif theirs is None:
                winner = ours
            else:
                reason = ConflictReason.CONFLICTING_CHANGES
        elif ours is None:
            if t_sig == b_sig:
                # Ours deleted it; theirs left it alone.
                pass
            else:
                reason = ConflictReason.DELETE_MODIFY
        elif theirs is None:
            if o_sig == b_sig:
                # Theirs deleted it; ours left it alone.
                pass
            else:
                reason = ConflictReason.DELETE_MODIFY
        elif o_sig == b_sig:
            # Only theirs changed.
            winner = theirs
        elif t_sig == b_sig:
            # Only ours changed.
            winner = ours
        else:
            reason = ConflictReason.CONFLICTING_CHANGES
        if reason is not None:
            conflicts.append(_conflict(reason, key, base, ours, theirs, origin))
        elif winner is not None:
            merged[key] = winner
    return merged, conflicts


def _group_by_name(
    units: dict[_UnitKey, _Unit],
) -> dict[dns.name.Name, list[_Unit]]:
    names: dict[dns.name.Name, list[_Unit]] = {}
    for unit in units.values():
        names.setdefault(unit.key.name, []).append(unit)
    for group in names.values():
        group.sort(key=lambda u: (u.key.rdtype, u.key.covers))
    return names


def _check_cname_coexistence(
    merged: dict[_UnitKey, _Unit],
    conflicting_keys: set[_UnitKey],
    base_units: dict[_UnitKey, _Unit],
    ours_units: dict[_UnitKey, _Unit],
    theirs_units: dict[_UnitKey, _Unit],
    origin: dns.name.Name,
) -> list[MergeConflict]:
    conflicts: list[MergeConflict] = []
    by_name = _group_by_name(merged)
    for name in sorted(by_name):
        units = by_name[name]
        cname = next(
            (u for u in units if u.key.rdtype == dns.rdatatype.RdataType.CNAME),
            None,
        )
        if cname is None:
            continue
        forbidden = [
            u
            for u in units
            if u is not cname
            and dns.node.NodeKind.classify(u.key.rdtype, u.key.covers)
            == dns.node.NodeKind.REGULAR
        ]
        if not forbidden:
            continue
        cname_key = _UnitKey(name, dns.rdatatype.RdataType.CNAME, dns.rdatatype.NONE)
        reported_cname = cname_key in conflicting_keys
        for unit in units:
            if (
                unit is cname
                or dns.node.NodeKind.classify(unit.key.rdtype, unit.key.covers)
                != dns.node.NodeKind.REGULAR
            ):
                continue
            key = unit.key
            if key in conflicting_keys:
                continue
            conflicts.append(
                _conflict(
                    ConflictReason.CNAME_AND_OTHER_DATA,
                    key,
                    base_units.get(key),
                    ours_units.get(key),
                    theirs_units.get(key),
                    origin,
                    detail=(
                        "node coexists with a CNAME and a "
                        f"{dns.rdatatype.to_text(unit.key.rdtype)} RRset"
                    ),
                )
            )
        if not reported_cname:
            # Report the CNAME half once as well, so the caller can see
            # both sides of the constraint violation even though the two
            # RRsets have different (type) identities.
            conflicts.append(
                _conflict(
                    ConflictReason.CNAME_AND_OTHER_DATA,
                    cname_key,
                    base_units.get(cname_key),
                    ours_units.get(cname_key),
                    theirs_units.get(cname_key),
                    origin,
                    detail="CNAME coexists with other data at the node",
                )
            )
    return conflicts


def _soa_unit(units: dict[_UnitKey, _Unit], origin: dns.name.Name) -> _Unit | None:
    return units.get(
        _UnitKey(
            origin,
            dns.rdatatype.RdataType.SOA,
            dns.rdatatype.NONE,
        )
    )


def _ns_unit(units: dict[_UnitKey, _Unit], origin: dns.name.Name) -> _Unit | None:
    return units.get(
        _UnitKey(
            origin,
            dns.rdatatype.RdataType.NS,
            dns.rdatatype.NONE,
        )
    )


def _serial_of(unit: _Unit | None) -> int | None:
    if unit is None:
        return None
    soa = unit.rdatas[0]
    assert isinstance(soa, dns.rdtypes.ANY.SOA.SOA)
    return int(soa.serial)


def _check_serial(
    base_units: dict[_UnitKey, _Unit],
    ours_units: dict[_UnitKey, _Unit],
    theirs_units: dict[_UnitKey, _Unit],
    origin: dns.name.Name,
    serial_policy: SerialPolicy,
) -> tuple[int | None, MergeConflict | None]:
    base_serial = _serial_of(_soa_unit(base_units, origin))
    ours_serial = _serial_of(_soa_unit(ours_units, origin))
    theirs_serial = _serial_of(_soa_unit(theirs_units, origin))
    chosen = serial_policy(base_serial, ours_serial, theirs_serial)
    # The chosen serial must not be earlier, in serial arithmetic, than
    # any serial a branch was actually using.  Taking the plain integer
    # maximum is explicitly not done.
    offending: list[tuple[str, int]] = []
    for label, branch_serial in (
        ("ours", ours_serial),
        ("theirs", theirs_serial),
    ):
        if branch_serial is not None and dns.serial.Serial(chosen) < dns.serial.Serial(
            branch_serial
        ):
            offending.append((label, branch_serial))
    if offending:
        detail = (
            f"serial {chosen} is earlier than "
            + " and ".join(f"{label} serial {serial}" for label, serial in offending)
            + " in serial number arithmetic"
        )
        key = _UnitKey(
            origin,
            dns.rdatatype.RdataType.SOA,
            dns.rdatatype.NONE,
        )
        conflict = _conflict(
            ConflictReason.INVALID_SERIAL,
            key,
            _soa_unit(base_units, origin),
            _soa_unit(ours_units, origin),
            _soa_unit(theirs_units, origin),
            origin,
            detail=detail,
        )
        return None, conflict
    return chosen, None


def _origin_conflict(
    reason: ConflictReason,
    origin: dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    base_units: dict[_UnitKey, _Unit],
    ours_units: dict[_UnitKey, _Unit],
    theirs_units: dict[_UnitKey, _Unit],
    detail: str | None = None,
) -> MergeConflict:
    key = _UnitKey(origin, rdtype, dns.rdatatype.NONE)
    return _conflict(
        reason,
        key,
        base_units.get(key),
        ours_units.get(key),
        theirs_units.get(key),
        origin,
        detail=detail,
    )


def _check_origin_and_serial(
    merged: dict[_UnitKey, _Unit],
    conflicting_keys: set[_UnitKey],
    base_units: dict[_UnitKey, _Unit],
    ours_units: dict[_UnitKey, _Unit],
    theirs_units: dict[_UnitKey, _Unit],
    origin: dns.name.Name,
    serial_policy: SerialPolicy,
) -> tuple[int | None, list[MergeConflict]]:
    conflicts: list[MergeConflict] = []
    chosen_serial: int | None = None
    soa_key = _UnitKey(origin, dns.rdatatype.RdataType.SOA, dns.rdatatype.NONE)
    if soa_key not in conflicting_keys:
        merged_soa = _soa_unit(merged, origin)
        if merged_soa is None:
            conflicts.append(
                _origin_conflict(
                    ConflictReason.NO_SOA,
                    origin,
                    dns.rdatatype.RdataType.SOA,
                    base_units,
                    ours_units,
                    theirs_units,
                )
            )
        else:
            if len(merged_soa.rdatas) != 1:
                conflicts.append(
                    _origin_conflict(
                        ConflictReason.INVALID_SOA,
                        origin,
                        dns.rdatatype.RdataType.SOA,
                        base_units,
                        ours_units,
                        theirs_units,
                        detail=(
                            f"exactly one SOA rdata is required, found "
                            f"{len(merged_soa.rdatas)}"
                        ),
                    )
                )
            else:
                chosen_serial, serial_conflict = _check_serial(
                    base_units,
                    ours_units,
                    theirs_units,
                    origin,
                    serial_policy,
                )
                if serial_conflict is not None:
                    conflicts.append(serial_conflict)
    ns_key = _UnitKey(origin, dns.rdatatype.RdataType.NS, dns.rdatatype.NONE)
    if ns_key not in conflicting_keys:
        merged_ns = _ns_unit(merged, origin)
        if merged_ns is None or len(merged_ns.rdatas) == 0:
            conflicts.append(
                _origin_conflict(
                    ConflictReason.NO_NS,
                    origin,
                    dns.rdatatype.RdataType.NS,
                    base_units,
                    ours_units,
                    theirs_units,
                )
            )
    # A CNAME at the origin can never be valid.
    cname_key = _UnitKey(origin, dns.rdatatype.RdataType.CNAME, dns.rdatatype.NONE)
    if cname_key in merged and cname_key not in conflicting_keys:
        conflicts.append(
            _origin_conflict(
                ConflictReason.CNAME_AND_OTHER_DATA,
                origin,
                dns.rdatatype.RdataType.CNAME,
                base_units,
                ours_units,
                theirs_units,
                detail="the zone origin may not be a CNAME",
            )
        )
    return chosen_serial, conflicts


def _absolute_rdata(rdata: dns.rdata.Rdata, origin: dns.name.Name) -> dns.rdata.Rdata:
    """Return an equivalent rdata whose embedded names are absolute and
    in DNSSEC canonical form, by a round-trip through canonical wire
    format.
    """

    wire = rdata.to_digestable(origin)
    return dns.rdata.from_wire(
        rdata.rdclass,
        rdata.rdtype,
        wire,
        0,
        len(wire),
    )


def _build_merged_zone(
    merged: dict[_UnitKey, _Unit],
    origin: dns.name.Name,
    rdclass: dns.rdataclass.RdataClass,
    relativize: bool,
    serial: int | None,
) -> dns.zone.Zone:
    zone = dns.zone.Zone(origin, rdclass, relativize=relativize)
    with zone.writer(True) as txn:
        for key in sorted(merged):
            unit = merged[key]
            rdataset = dns.rdataset.Rdataset(
                unit.rdclass, key.rdtype, key.covers, unit.ttl
            )
            for rdata in unit.rdatas:
                rd = _absolute_rdata(rdata, origin)
                if serial is not None and key.rdtype == dns.rdatatype.RdataType.SOA:
                    assert isinstance(rd, dns.rdtypes.ANY.SOA.SOA)
                    rd = rd.replace(serial=serial)
                rdataset.add(rd)
            if relativize:
                owner = key.name.relativize(origin)
            else:
                owner = key.name
            txn.replace(owner, rdataset)
    return zone


def _conflict_sort_key(conflict: MergeConflict):
    return (
        conflict.name,
        conflict.rdtype,
        conflict.covers,
        conflict.reason.value,
        (conflict.detail or ""),
    )


def try_merge(
    base: dns.zone.Zone,
    ours: dns.zone.Zone,
    theirs: dns.zone.Zone,
    serial_policy: SerialPolicy = latest_serial,
    relativize: bool | None = None,
) -> MergeResult:
    """Three-way merge three zones, returning a :py:class:`MergeResult`.

    The three input zones are never modified.

    :param base: The common ancestor zone.
    :type base: :py:class:`dns.zone.Zone`
    :param ours: The first branch zone.
    :type ours: :py:class:`dns.zone.Zone`
    :param theirs: The second branch zone.
    :type theirs: :py:class:`dns.zone.Zone`
    :param serial_policy: A callable taking ``(base_serial, ours_serial,
        theirs_serial)`` (each an ``int`` or ``None``) and returning the
        serial to use in the merged zone.  The chosen serial must be at
        least as large as every branch serial according to RFC 1982
        serial number arithmetic.  The default is
        :py:func:`latest_serial`, which selects the latest branch serial
        using serial arithmetic.  Other provided policies are
        :py:func:`ours_serial`, :py:func:`theirs_serial`, and
        :py:func:`increment_serial`.
    :type serial: callable
    :param relativize: Whether the returned zone should relativize names
        to its origin.  If ``None`` (the default), the *base* zone's
        setting is used.
    :type relativize: bool or None
    :rtype: :py:class:`MergeResult`
    :raises dns.zonemerge.MergeError: if the request is invalid, e.g.
        the zones do not share an origin or rdata class.
    """

    for label, candidate in (
        ("base", base),
        ("ours", ours),
        ("theirs", theirs),
    ):
        if not isinstance(candidate, dns.zone.Zone):
            raise MergeError(f"the {label} input is not a dns.zone.Zone")
        if candidate.origin is None:
            raise MergeError(f"the {label} zone has no origin")
    origin = base.origin
    assert origin is not None
    for label, candidate in (("ours", ours), ("theirs", theirs)):
        assert candidate.origin is not None
        if candidate.origin.canonicalize() != origin.canonicalize():
            raise MergeError(
                f"the {label} zone origin {candidate.origin} does not "
                f"match the base origin {origin}"
            )
        if candidate.rdclass != base.rdclass:
            raise MergeError(
                f"the {label} zone class {candidate.rdclass} does not "
                f"match the base class {base.rdclass}"
            )
    if relativize is None:
        relativize = base.relativize

    base_units = _index_zone(base, origin)
    ours_units = _index_zone(ours, origin)
    theirs_units = _index_zone(theirs, origin)

    merged, unit_conflicts = _merge_units(base_units, ours_units, theirs_units, origin)
    conflicts: list[MergeConflict] = list(unit_conflicts)
    conflicting_keys = {unit_key(c) for c in unit_conflicts}

    conflicts.extend(
        _check_cname_coexistence(
            merged,
            conflicting_keys,
            base_units,
            ours_units,
            theirs_units,
            origin,
        )
    )
    chosen_serial, origin_conflicts = _check_origin_and_serial(
        merged,
        conflicting_keys,
        base_units,
        ours_units,
        theirs_units,
        origin,
        serial_policy,
    )
    conflicts.extend(origin_conflicts)

    if conflicts:
        conflicts.sort(key=_conflict_sort_key)
        return MergeResult(None, tuple(conflicts))

    merged_zone = _build_merged_zone(
        merged, origin, base.rdclass, relativize, chosen_serial
    )
    return MergeResult(merged_zone, ())


def unit_key(conflict: MergeConflict) -> _UnitKey:
    return _UnitKey(conflict.name, conflict.rdtype, conflict.covers)


def merge(
    base: dns.zone.Zone,
    ours: dns.zone.Zone,
    theirs: dns.zone.Zone,
    serial_policy: SerialPolicy = latest_serial,
    relativize: bool | None = None,
) -> dns.zone.Zone:
    """Three-way merge three zones.

    This is a convenience wrapper around :py:func:`try_merge` which
    returns the merged zone directly or raises
    :py:class:`MergeConflicts`.

    :param base: The common ancestor zone.
    :type base: :py:class:`dns.zone.Zone`
    :param ours: The first branch zone.
    :type ours: :py:class:`dns.zone.Zone`
    :param theirs: The second branch zone.
    :type theirs: :py:class:`dns.zone.Zone`
    :param serial_policy: The SOA serial policy; see
        :py:func:`try_merge`.
    :param relativize: Whether the returned zone should relativize
        names; see :py:func:`try_merge`.
    :rtype: :py:class:`dns.zone.Zone`
    :raises dns.zonemerge.MergeConflicts: if the merge has conflicts.
    :raises dns.zonemerge.MergeError: if the request is invalid.
    """

    return try_merge(base, ours, theirs, serial_policy, relativize).raise_if_conflicts()
