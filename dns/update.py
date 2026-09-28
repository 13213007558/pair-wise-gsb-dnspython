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

from collections.abc import Iterable
from typing import Any, cast

import dns.enum
import dns.exception
import dns.message
import dns.name
import dns.opcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rcode
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.serial
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


# Rdata types that may coexist with a CNAME RRset at the same name.
_cname_compatible_types = {
    dns.rdatatype.CNAME,
    dns.rdatatype.RRSIG,
    dns.rdatatype.NSEC,
    dns.rdatatype.KEY,
}


def _rdata_digest(rd: dns.rdata.Rdata) -> bytes:
    # A class-independent canonical form of the rdata, suitable for
    # comparing rdata that may have been created with different classes
    # (e.g. the NONE class used for deletions in update messages).
    try:
        return rd.to_digestable()
    except dns.name.NeedAbsoluteNameOrOrigin:
        return rd.to_digestable(dns.name.root)


def _rdata_set(rdatas: Iterable[dns.rdata.Rdata]) -> set[bytes]:
    return {_rdata_digest(rd) for rd in rdatas}


def apply(
    update: UpdateMessage, zone: dns.transaction.TransactionManager
) -> dns.rcode.Rcode:
    """Apply a dynamic update message to a zone, as a server would.

    The *update* message is processed as specified in RFC 2136: its
    prerequisites are checked, and if they are all satisfied, its updates
    are applied to *zone* in a single write transaction.  The message is
    assumed to have already been authenticated and authorized by the
    caller.  The message is not modified, and may be applied again; the
    result of each application depends on the state of the zone at that
    time.

    Prerequisite matching is by exact name: wildcard names are literal,
    and CNAMEs are not followed.  Value-dependent prerequisites compare
    the whole set of rdata, ignoring TTLs.  If any prerequisite fails,
    the zone is not changed and an appropriate rcode is returned.

    The protocol's special rules are observed: the SOA and NS RRsets at
    the zone apex cannot be deleted, an SOA RR added at the apex replaces
    the current SOA only if it advances the serial (per RFC 1982), and
    updates that would make a CNAME coexist with other data are ignored.

    :param update: the update message to apply
    :type update: :py:class:`dns.update.UpdateMessage`
    :param zone: the zone (or other transaction manager) to update
    :type zone: :py:class:`dns.transaction.TransactionManager`
    :returns: the rcode resulting from processing the update
    :rtype: :py:class:`dns.rcode.Rcode`
    """

    if update.opcode() != dns.opcode.UPDATE or len(update.zone) != 1:
        return dns.rcode.FORMERR
    zone_rrset = update.zone[0]
    if zone_rrset.rdtype != dns.rdatatype.SOA:
        return dns.rcode.FORMERR
    (origin, relativize, effective_origin) = zone.origin_information()
    if origin is None or zone_rrset.name != origin:
        return dns.rcode.NOTAUTH
    rdclass = zone.get_class()
    if zone_rrset.rdclass != rdclass:
        return dns.rcode.NOTAUTH

    def in_zone(name: dns.name.Name) -> bool:
        return name.is_absolute() and name.is_subdomain(origin)

    def effective_class(rrset: dns.rrset.RRset) -> dns.rdataclass.RdataClass:
        # On the wire, the ANY or NONE class marks a delete; in an
        # UpdateMessage it is stored in the rrset's "deleting" attribute.
        if rrset.deleting is not None:
            return rrset.deleting
        return rrset.rdclass

    # Check the prerequisite section for format errors and out-of-zone
    # names.
    for rrset in update.prerequisite:
        if not in_zone(rrset.name):
            return dns.rcode.NOTZONE
        if rrset.ttl != 0:
            return dns.rcode.FORMERR
        cls = effective_class(rrset)
        if cls in (dns.rdataclass.ANY, dns.rdataclass.NONE):
            if len(rrset) != 0:
                return dns.rcode.FORMERR
        elif cls != rdclass:
            return dns.rcode.FORMERR

    # Check the update section for format errors and out-of-zone names
    # before changing anything.
    for rrset in update.update:
        if not in_zone(rrset.name):
            return dns.rcode.NOTZONE
        cls = effective_class(rrset)
        if cls == rdclass:
            if rrset.ttl == 0 or len(rrset) == 0:
                return dns.rcode.FORMERR
            if rrset.rdtype == dns.rdatatype.SOA and (
                len(rrset) != 1 or rrset.name != origin
            ):
                return dns.rcode.FORMERR
        elif cls == dns.rdataclass.NONE:
            if rrset.ttl != 0 or len(rrset) == 0:
                return dns.rcode.FORMERR
        elif cls == dns.rdataclass.ANY:
            if rrset.ttl != 0 or len(rrset) != 0:
                return dns.rcode.FORMERR
        else:
            return dns.rcode.FORMERR

    def transaction_name(name: dns.name.Name) -> dns.name.Name:
        # Convert the absolute names in the message into the form used
        # by the transaction manager.
        if relativize:
            return name.relativize(origin)
        return name

    def check_prerequisites(txn: dns.transaction.Transaction) -> dns.rcode.Rcode:
        # Value-dependent prerequisites with the same name and type are
        # aggregated; the whole set of rdata must match, ignoring TTLs.
        required: dict[
            tuple[
                dns.name.Name,
                dns.rdatatype.RdataType,
                dns.rdatatype.RdataType,
            ],
            set[bytes],
        ] = {}
        for rrset in update.prerequisite:
            if effective_class(rrset) == rdclass:
                key = (
                    transaction_name(rrset.name),
                    rrset.rdtype,
                    rrset.covers,
                )
                if key not in required:
                    required[key] = set()
                required[key].update(_rdata_set(rrset))

        checked: set[
            tuple[
                dns.name.Name,
                dns.rdatatype.RdataType,
                dns.rdatatype.RdataType,
            ]
        ] = set()
        for rrset in update.prerequisite:
            tname = transaction_name(rrset.name)
            cls = effective_class(rrset)
            if cls == dns.rdataclass.ANY:
                if rrset.rdtype == dns.rdatatype.ANY:
                    # Name is in use.
                    if not txn.name_exists(tname):
                        return dns.rcode.NXDOMAIN
                # RRset exists (value independent).
                elif txn.get(tname, rrset.rdtype, rrset.covers) is None:
                    return dns.rcode.NXRRSET
            elif cls == dns.rdataclass.NONE:
                if rrset.rdtype == dns.rdatatype.ANY:
                    # Name is not in use.
                    if txn.name_exists(tname):
                        return dns.rcode.YXDOMAIN
                # RRset does not exist.
                elif txn.get(tname, rrset.rdtype, rrset.covers) is not None:
                    return dns.rcode.YXRRSET
            else:
                key = (tname, rrset.rdtype, rrset.covers)
                if key in checked:
                    continue
                checked.add(key)
                existing = txn.get(tname, rrset.rdtype, rrset.covers)
                if existing is None or _rdata_set(existing) != required[key]:
                    return dns.rcode.NXRRSET
        return dns.rcode.NOERROR

    def cname_allows(
        txn: dns.transaction.Transaction,
        tname: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
    ) -> bool:
        # Adding RRs must not cause a CNAME to coexist with other data.
        node = txn.get_node(tname)
        if node is None:
            return True
        existing_types = {rds.rdtype for rds in node}
        if rdtype == dns.rdatatype.CNAME:
            return existing_types <= _cname_compatible_types
        if rdtype in _cname_compatible_types:
            return True
        return dns.rdatatype.CNAME not in existing_types

    # Messages built with UpdateMessage, or parsed from the wire, have
    # one rrset per RR, so merge consecutive rrsets that describe the
    # same add or delete operation, preserving the order of operations.
    operations: list[
        tuple[
            tuple[
                dns.name.Name,
                dns.rdataclass.RdataClass,
                dns.rdatatype.RdataType,
                dns.rdatatype.RdataType,
            ],
            list[dns.rdata.Rdata],
            int,
        ]
    ] = []
    for rrset in update.update:
        cls = effective_class(rrset)
        key = (rrset.name, cls, rrset.rdtype, rrset.covers)
        if operations and operations[-1][0] == key:
            operations[-1][1].extend(rrset)
        else:
            operations.append((key, list(rrset), rrset.ttl))

    def apply_updates(txn: dns.transaction.Transaction) -> None:
        for (name, cls, rdtype, covers), rdatas, ttl in operations:
            tname = transaction_name(name)
            at_apex = tname == effective_origin
            if cls == rdclass:
                # Add RRs to an RRset.
                if rdtype == dns.rdatatype.SOA:
                    # An SOA added at the apex replaces the current SOA,
                    # but only if it advances the serial.
                    new_soa = cast(dns.rdtypes.ANY.SOA.SOA, rdatas[0])
                    existing = txn.get(tname, dns.rdatatype.SOA)
                    if existing is not None:
                        old_soa = cast(dns.rdtypes.ANY.SOA.SOA, existing[0])
                        if not dns.serial.Serial(new_soa.serial) > dns.serial.Serial(
                            old_soa.serial
                        ):
                            continue
                    txn.replace(tname, ttl, *rdatas)
                elif cname_allows(txn, tname, rdtype):
                    txn.add(tname, ttl, *rdatas)
            elif cls == dns.rdataclass.NONE:
                # Delete RRs from an RRset.
                if at_apex and rdtype == dns.rdatatype.SOA:
                    continue
                existing = txn.get(tname, rdtype, covers)
                if existing is None:
                    continue
                unwanted = _rdata_set(rdatas)
                remaining = [rd for rd in existing if _rdata_digest(rd) not in unwanted]
                if len(remaining) == len(existing):
                    continue
                if at_apex and rdtype == dns.rdatatype.NS and not remaining:
                    # The last NS RR at the apex may not be deleted.
                    continue
                if remaining:
                    txn.replace(tname, existing.ttl, *remaining)
                else:
                    txn.delete(tname, rdtype, covers)
            elif rdtype == dns.rdatatype.ANY:
                # Delete all RRsets at the name, except the apex SOA and NS.
                if at_apex:
                    node = txn.get_node(tname)
                    if node is not None:
                        for rds in node:
                            if rds.rdtype not in (
                                dns.rdatatype.SOA,
                                dns.rdatatype.NS,
                            ):
                                txn.delete(tname, rds.rdtype, rds.covers)
                else:
                    txn.delete(tname)
            elif not (at_apex and rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS)):
                # Delete an RRset.
                txn.delete(tname, rdtype, covers)

    with zone.writer() as txn:
        rcode = check_prerequisites(txn)
        if rcode != dns.rcode.NOERROR:
            txn.rollback()
            return rcode
        apply_updates(txn)
    return dns.rcode.NOERROR


### BEGIN generated UpdateSection constants

ZONE = UpdateSection.ZONE
PREREQ = UpdateSection.PREREQ
UPDATE = UpdateSection.UPDATE
ADDITIONAL = UpdateSection.ADDITIONAL

### END generated UpdateSection constants
