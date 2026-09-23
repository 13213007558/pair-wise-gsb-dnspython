# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2007, 2009-2011 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""DNS Dynamic Update Support"""

from typing import Any

import dns.enum
import dns.exception
import dns.message
import dns.name
import dns.node
import dns.opcode
import dns.rdata
import dns.rdataclass
import dns.rcode
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.transaction
import dns.tsig


class UpdateSection(dns.enum.IntEnum):
    """Update sections"""

    ZONE = 0
    PREREQ = 1
    UPDATE = 2
    ADDITIONAL = 3

    @classmethod
    def _maximum(cls):
        return 3


class UpdateMessage(dns.message.Message):  # lgtm[py/missing-equals]
    # ignore the mypy error here as we mean to use a different enum
    _section_enum = UpdateSection  # pyright: ignore

    def __init__(
        self,
        zone: dns.name.Name | str | None = None,
        rdclass: dns.rdataclass.RdataClass = dns.rdataclass.IN,
        keyring: Any | None = None,
        keyname: dns.name.Name | None = None,
        keyalgorithm: dns.name.Name | str = dns.tsig.default_algorithm,
        id: int | None = None,
    ):
        """Initialize a new DNS Update object.

        See the documentation of the Message class for a complete
        description of the keyring dictionary.

        :param zone: The zone which is being updated. ``None`` should only be
            used by dnspython's message constructors, as a zone is required for
            the convenience methods like ``add()``, ``replace()``, etc.
        :type zone: :py:class:`dns.name.Name`, str, or ``None``
        :param rdclass: The class of the zone.
        :type rdclass: int or str

        The *keyring*, *keyname*, and *keyalgorithm* parameters are passed to
        ``use_tsig()``; see its documentation for details.
        """
        super().__init__(id=id)
        self.flags |= dns.opcode.to_flags(dns.opcode.UPDATE)
        if isinstance(zone, str):
            zone = dns.name.from_text(zone)
        self.origin = zone
        rdclass = dns.rdataclass.RdataClass.make(rdclass)
        self.zone_rdclass = rdclass
        if self.origin:
            self.find_rrset(
                self.zone,
                self.origin,
                rdclass,
                dns.rdatatype.SOA,
                create=True,
                force_unique=True,
            )
        if keyring is not None:
            self.use_tsig(keyring, keyname, algorithm=keyalgorithm)

    @property
    def zone(self) -> list[dns.rrset.RRset]:
        """The zone section."""
        return self.sections[0]

    @zone.setter
    def zone(self, v):
        self.sections[0] = v

    @property
    def prerequisite(self) -> list[dns.rrset.RRset]:
        """The prerequisite section."""
        return self.sections[1]

    @prerequisite.setter
    def prerequisite(self, v):
        self.sections[1] = v

    @property
    def update(self) -> list[dns.rrset.RRset]:
        """The update section."""
        return self.sections[2]

    @update.setter
    def update(self, v):
        self.sections[2] = v

    def _add_rr(self, name, ttl, rd, deleting=None, section=None):
        """Add a single RR to the update section."""

        if section is None:
            section = self.update
        covers = rd.covers()
        rrset = self.find_rrset(
            section, name, self.zone_rdclass, rd.rdtype, covers, deleting, True, True
        )
        rrset.add(rd, ttl)

    def _add(self, replace, section, name, *args):
        """Add records.

        *replace* is the replacement mode.  If ``False``,
        RRs are added to an existing RRset; if ``True``, the RRset
        is replaced with the specified contents.  The second
        argument is the section to add to.  The third argument
        is always a name.  The other arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...
        """

        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if isinstance(args[0], dns.rdataset.Rdataset):
            for rds in args:
                if replace:
                    self.delete(name, rds.rdtype)
                for rd in rds:
                    self._add_rr(name, rds.ttl, rd, section=section)
        else:
            args = list(args)
            ttl = int(args.pop(0))
            if isinstance(args[0], dns.rdata.Rdata):
                if replace:
                    self.delete(name, args[0].rdtype)
                for rd in args:
                    self._add_rr(name, ttl, rd, section=section)
            else:
                rdtype = dns.rdatatype.RdataType.make(args.pop(0))
                if replace:
                    self.delete(name, rdtype)
                for s in args:
                    rd = dns.rdata.from_text(self.zone_rdclass, rdtype, s, self.origin)
                    self._add_rr(name, ttl, rd, section=section)

    def add(self, name: dns.name.Name | str, *args: Any) -> None:
        """Add records.

        The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...
        """

        self._add(False, self.update, name, *args)

    def delete(self, name: dns.name.Name | str, *args: Any) -> None:
        """Delete records.

        The first argument is always a name.  The other
        arguments can be:

                - *empty*

                - rdataset...

                - rdata...

                - rdtype, [string...]
        """

        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if len(args) == 0:
            self.find_rrset(
                self.update,
                name,
                dns.rdataclass.ANY,
                dns.rdatatype.ANY,
                dns.rdatatype.NONE,
                dns.rdataclass.ANY,
                True,
                True,
            )
        elif isinstance(args[0], dns.rdataset.Rdataset):
            for rds in args:
                for rd in rds:
                    self._add_rr(name, 0, rd, dns.rdataclass.NONE)
        else:
            largs = list(args)
            if isinstance(largs[0], dns.rdata.Rdata):
                for rd in largs:
                    self._add_rr(name, 0, rd, dns.rdataclass.NONE)
            else:
                rdtype = dns.rdatatype.RdataType.make(largs.pop(0))
                if len(largs) == 0:
                    self.find_rrset(
                        self.update,
                        name,
                        self.zone_rdclass,
                        rdtype,
                        dns.rdatatype.NONE,
                        dns.rdataclass.ANY,
                        True,
                        True,
                    )
                else:
                    for s in largs:
                        rd = dns.rdata.from_text(
                            self.zone_rdclass,
                            rdtype,
                            s,  # pyright: ignore[arg-type]
                            self.origin,
                        )
                        self._add_rr(name, 0, rd, dns.rdataclass.NONE)

    def replace(self, name: dns.name.Name | str, *args: Any) -> None:
        """Replace records.

        The first argument is always a name.  The other
        arguments can be:

                - rdataset...

                - ttl, rdata...

                - ttl, rdtype, string...

        Note that if you want to replace the entire node, you should do
        a delete of the name followed by one or more calls to add.
        """

        self._add(True, self.update, name, *args)

    def present(self, name: dns.name.Name | str, *args: Any) -> None:
        """Require that an owner name (and optionally an rdata type,
        or specific rdataset) exists as a prerequisite to the
        execution of the update.

        The first argument is always a name.
        The other arguments can be:

                - rdataset...

                - rdata...

                - rdtype, string...
        """

        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if len(args) == 0:
            self.find_rrset(
                self.prerequisite,
                name,
                dns.rdataclass.ANY,
                dns.rdatatype.ANY,
                dns.rdatatype.NONE,
                None,
                True,
                True,
            )
        elif (
            isinstance(args[0], dns.rdataset.Rdataset)
            or isinstance(args[0], dns.rdata.Rdata)
            or len(args) > 1
        ):
            if not isinstance(args[0], dns.rdataset.Rdataset):
                # Add a 0 TTL
                largs = list(args)
                largs.insert(0, 0)  # pyright: ignore[arg-type]
                self._add(False, self.prerequisite, name, *largs)
            else:
                self._add(False, self.prerequisite, name, *args)
        else:
            rdtype = dns.rdatatype.RdataType.make(args[0])
            self.find_rrset(
                self.prerequisite,
                name,
                dns.rdataclass.ANY,
                rdtype,
                dns.rdatatype.NONE,
                None,
                True,
                True,
            )

    def absent(
        self,
        name: dns.name.Name | str,
        rdtype: dns.rdatatype.RdataType | str | None = None,
    ) -> None:
        """Require that an owner name (and optionally an rdata type) does
        not exist as a prerequisite to the execution of the update."""

        if isinstance(name, str):
            name = dns.name.from_text(name, None)
        if rdtype is None:
            self.find_rrset(
                self.prerequisite,
                name,
                dns.rdataclass.NONE,
                dns.rdatatype.ANY,
                dns.rdatatype.NONE,
                None,
                True,
                True,
            )
        else:
            rdtype = dns.rdatatype.RdataType.make(rdtype)
            self.find_rrset(
                self.prerequisite,
                name,
                dns.rdataclass.NONE,
                rdtype,
                dns.rdatatype.NONE,
                None,
                True,
                True,
            )

    def _get_one_rr_per_rrset(self, value):
        # Updates are always one_rr_per_rrset
        return True

    def _parse_rr_header(self, section, name, rdclass, rdtype):  # pyright: ignore
        deleting = None
        empty = False
        if section == UpdateSection.ZONE:
            if (
                dns.rdataclass.is_metaclass(rdclass)
                or rdtype != dns.rdatatype.SOA
                or self.zone
            ):
                raise dns.exception.FormError
        else:
            if not self.zone:
                raise dns.exception.FormError
            if rdclass in (dns.rdataclass.ANY, dns.rdataclass.NONE):
                deleting = rdclass
                rdclass = self.zone[0].rdclass
                empty = (
                    deleting == dns.rdataclass.ANY or section == UpdateSection.PREREQ
                )
        return (rdclass, rdtype, deleting, empty)


# backwards compatibility
Update = UpdateMessage


def _absolutize(name: dns.name.Name, origin: dns.name.Name) -> dns.name.Name:
    if not name.is_absolute():
        return name.concatenate(origin)
    return name


def _effective_class(rrset: dns.rrset.RRset) -> dns.rdataclass.RdataClass:
    # Update and prerequisite section RRsets represent the ANY and NONE
    # classes either directly as the rrset class (messages built with the
    # convenience methods) or in the "deleting" attribute (messages parsed
    # from the wire, and delete operations in the update section).
    if rrset.deleting is not None:
        return rrset.deleting
    return rrset.rdclass


def _check_prerequisites(
    txn: dns.transaction.Transaction, origin: dns.name.Name, update: UpdateMessage
) -> dns.rcode.Rcode | None:
    """Check all of the prerequisites of an update message, returning an
    rcode if any of them is not satisfied, or None if all are."""
    # Value-dependent prerequisites are aggregated by (name, rdtype), as
    # the RRs of a set may appear as multiple one-RR rrsets in the
    # prerequisite section.
    required: dict[tuple[dns.name.Name, dns.rdatatype.RdataType], set] = {}
    for rrset in update.prerequisite:
        name = _absolutize(rrset.name, origin)
        rdclass = _effective_class(rrset)
        rdtype = rrset.rdtype
        if rdclass == dns.rdataclass.ANY:
            if rdtype == dns.rdatatype.ANY:
                # "Name is in use"
                if not txn.name_exists(name):
                    return dns.rcode.NXDOMAIN
            else:
                # "RRset exists (value independent)"
                if txn.get(name, rdtype) is None:
                    return dns.rcode.NXRRSET
        elif rdclass == dns.rdataclass.NONE:
            if rdtype == dns.rdatatype.ANY:
                # "Name is not in use"
                if txn.name_exists(name):
                    return dns.rcode.YXDOMAIN
            else:
                # "RRset does not exist"
                if txn.get(name, rdtype) is not None:
                    return dns.rcode.YXRRSET
        else:
            # "RRset exists (value dependent)"
            key = (name, rdtype)
            if key in required:
                required[key].update(rrset)
            else:
                required[key] = set(rrset)
    for (name, rdtype), rdata in required.items():
        # TTLs are ignored and the order of the RRs is not significant;
        # the sets must be equal.
        existing = txn.get(name, rdtype)
        if existing is None or set(existing) != rdata:
            return dns.rcode.NXRRSET
    return None


def _cname_conflict(
    txn: dns.transaction.Transaction,
    name: dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
) -> bool:
    """Would adding an RRset of the specified type at the name make a
    CNAME coexist with other data?"""
    kind = dns.node.NodeKind.classify(rdtype, dns.rdatatype.NONE)
    if kind == dns.node.NodeKind.NEUTRAL:
        return False
    node = txn.get_node(name)
    if node is None:
        return False
    for rds in node.rdatasets:
        rkind = dns.node.NodeKind.classify_rdataset(rds)
        if kind == dns.node.NodeKind.CNAME and rkind == dns.node.NodeKind.REGULAR:
            return True
        if kind == dns.node.NodeKind.REGULAR and rkind == dns.node.NodeKind.CNAME:
            return True
    return False


def _process_update(
    txn: dns.transaction.Transaction,
    origin: dns.name.Name,
    zone_rdclass: dns.rdataclass.RdataClass,
    rrset: dns.rrset.RRset,
) -> dns.rcode.Rcode | None:
    """Process one update section RRset, returning an rcode on failure,
    or None on success."""
    name = _absolutize(rrset.name, origin)
    if not name.is_subdomain(origin):
        return dns.rcode.NOTZONE
    rdclass = _effective_class(rrset)
    rdtype = rrset.rdtype
    if rdclass == zone_rdclass:
        # Add RRs to an RRset.  Additions that would make a CNAME
        # coexist with other data at the same node are ignored.
        if _cname_conflict(txn, name, rdtype):
            return None
        txn.add(name, rrset.ttl, *rrset)
    elif rdclass == dns.rdataclass.ANY:
        if rdtype == dns.rdatatype.ANY:
            # Delete all RRsets at a name.  The SOA and NS RRsets at the
            # zone apex are never deleted.
            if name == origin:
                node = txn.get_node(name)
                if node is not None:
                    for rds in node.rdatasets:
                        if rds.rdtype not in (dns.rdatatype.SOA, dns.rdatatype.NS):
                            txn.delete(name, rds.rdtype, rds.covers)
            else:
                txn.delete(name)
        else:
            # Delete an RRset.  The SOA and NS RRsets at the zone apex
            # cannot be deleted.
            if name == origin and rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS):
                return None
            txn.delete(name, rdtype)
    elif rdclass == dns.rdataclass.NONE:
        # Delete RRs from an RRset.  The SOA at the zone apex cannot be
        # deleted, and neither can the last apex NS RR.
        if name == origin and rdtype == dns.rdatatype.SOA:
            return None
        if name == origin and rdtype == dns.rdatatype.NS:
            existing = txn.get(name, rdtype)
            remaining = (
                [rd for rd in existing if rd not in rrset]
                if existing is not None
                else []
            )
            if len(remaining) == 0:
                return None
        txn.delete(name, *rrset)
    return None


def apply_update(
    update: UpdateMessage, zone: dns.transaction.TransactionManager
) -> dns.rcode.Rcode:
    """Apply a DNS dynamic update message to a zone.

    This implements the server-side protocol semantics of RFC 2136: the
    prerequisites of the message are checked against the zone as it exists
    before the update, and if they are all satisfied, the update section
    is applied in a single transaction.  If any prerequisite is not
    satisfied, or the update cannot be performed, the zone is left
    unchanged and an appropriate rcode is returned.

    Authentication (e.g. TSIG verification) and authorization policy are
    the responsibility of the caller; this function only implements the
    update protocol semantics.

    *update* is the :py:class:`dns.update.UpdateMessage` to apply.

    *zone* is a transaction manager, e.g. a :py:class:`dns.zone.Zone` or
    :py:class:`dns.versioned.Zone`, to which the update is applied.

    Returns :py:attr:`dns.rcode.Rcode.NOERROR` if the update was applied.
    Other possible returns are `FORMERR` (the zone section of the message
    is missing or has the wrong class), `NOTAUTH` (the message is not for
    this zone), `NOTZONE` (an update RR has an owner name outside the
    zone), and `NXDOMAIN`, `NXRRSET`, `YXDOMAIN`, or `YXRRSET` for
    prerequisite failures.
    """
    origin, _, _ = zone.origin_information()
    if origin is None:
        return dns.rcode.NOTAUTH
    if update.zone:
        zname = update.zone[0].name
        zclass = update.zone[0].rdclass
    elif update.origin is not None:
        zname = update.origin
        zclass = update.zone_rdclass
    else:
        return dns.rcode.FORMERR
    if _absolutize(zname, origin) != origin:
        return dns.rcode.NOTAUTH
    zone_rdclass = zone.get_class()
    if zclass != zone_rdclass:
        return dns.rcode.FORMERR
    with zone.writer() as txn:
        # All prerequisites are checked against the zone as it was
        # before any updates were applied.
        rcode = _check_prerequisites(txn, origin, update)
        if rcode is not None:
            txn.rollback()
            return rcode
        for rrset in update.update:
            rcode = _process_update(txn, origin, zone_rdclass, rrset)
            if rcode is not None:
                txn.rollback()
                return rcode
        txn.commit()
    return dns.rcode.NOERROR


### BEGIN generated UpdateSection constants

ZONE = UpdateSection.ZONE
PREREQ = UpdateSection.PREREQ
UPDATE = UpdateSection.UPDATE
ADDITIONAL = UpdateSection.ADDITIONAL

### END generated UpdateSection constants
