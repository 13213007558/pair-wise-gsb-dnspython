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


def _is_undeletable(
    rdtype: dns.rdatatype.RdataType, name: dns.name.Name, origin: dns.name.Name
) -> bool:
    # The SOA RRset and the zone apex NS RRset may not be deleted by a
    # dynamic update (RFC 2136 sections 3.4.2.3 - 3.4.2.5).
    return rdtype == dns.rdatatype.SOA or (
        rdtype == dns.rdatatype.NS and name == origin
    )


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

    def apply(self, manager: dns.transaction.TransactionManager) -> dns.rcode.Rcode:
        """Apply the update to a zone, checking prerequisites first.

        This implements the server-side update processing of RFC 2136.  The
        prerequisites in the message are checked against the zone's content
        prior to the update, and if they are all satisfied, the update
        section is applied in a single transaction.  If any prerequisite
        fails, or if the update section is invalid, the zone is left
        unchanged.

        Authentication and authorization, e.g. TSIG verification and
        deciding which identities are allowed to update, are the
        responsibility of the caller; this method only implements the
        protocol semantics.

        Note that the zone's SOA serial is not updated; the caller may do
        this, e.g. with :py:meth:`dns.transaction.Transaction.update_serial`,
        if desired.

        :param manager: The zone to update, typically a
            :py:class:`dns.zone.Zone` or :py:class:`dns.versioned.Zone`.
        :type manager: :py:class:`dns.transaction.TransactionManager`
        :returns: ``dns.rcode.NOERROR`` if the update was applied, or the
            rcode corresponding to the failure.
        :rtype: :py:class:`dns.rcode.Rcode`
        """
        if not self.zone:
            return dns.rcode.FORMERR
        zone_name = self.zone[0].name
        if not zone_name.is_absolute():
            return dns.rcode.FORMERR
        origin, _, _ = manager.origin_information()
        if origin is None or zone_name != origin:
            return dns.rcode.NOTAUTH
        if self.zone[0].rdclass != manager.get_class():
            return dns.rcode.FORMERR
        with manager.writer() as txn:
            rcode = self._check_prerequisites(txn, origin)
            if rcode is None:
                rcode = self._check_update_names(origin)
            if rcode is not None:
                txn.rollback()
                return rcode
            self._apply_updates(txn, origin)
        return dns.rcode.NOERROR

    def _absolute_name(self, name: dns.name.Name) -> dns.name.Name:
        if name.is_absolute():
            return name
        assert self.origin is not None
        return name.derelativize(self.origin)

    def _check_prerequisites(
        self, txn: dns.transaction.Transaction, origin: dns.name.Name
    ) -> dns.rcode.Rcode | None:
        # RFC 2136 section 3.2.  All prerequisites are checked against the
        # zone as it was before any updates were applied.
        expected: dict[
            tuple[dns.name.Name, dns.rdatatype.RdataType, dns.rdatatype.RdataType],
            set[dns.rdata.Rdata],
        ] = {}
        for rrset in self.prerequisite:
            name = self._absolute_name(rrset.name)
            if not name.is_subdomain(origin):
                return dns.rcode.NOTZONE
            if rrset.deleting is not None:
                rdclass = rrset.deleting
            else:
                rdclass = rrset.rdclass
            if rdclass == dns.rdataclass.ANY:
                if rrset.rdtype == dns.rdatatype.ANY:
                    # Name is in use.
                    if not txn.name_exists(name):
                        return dns.rcode.NXDOMAIN
                elif txn.get(name, rrset.rdtype, rrset.covers) is None:
                    # RRset exists (value independent).
                    return dns.rcode.NXRRSET
            elif rdclass == dns.rdataclass.NONE:
                if rrset.rdtype == dns.rdatatype.ANY:
                    # Name is not in use.
                    if txn.name_exists(name):
                        return dns.rcode.YXDOMAIN
                elif txn.get(name, rrset.rdtype, rrset.covers) is not None:
                    # RRset does not exist.
                    return dns.rcode.YXRRSET
            else:
                # RRset exists (value dependent).  The RRs accumulate into
                # a set per owner name and type, and are compared below.
                key = (name, rrset.rdtype, rrset.covers)
                expected.setdefault(key, set()).update(rrset)
        for (name, rdtype, covers), rdatas in expected.items():
            # The comparison is of the sets of RRs, ignoring TTLs and order.
            existing = txn.get(name, rdtype, covers)
            if existing is None or set(existing) != rdatas:
                return dns.rcode.NXRRSET
        return None

    def _check_update_names(self, origin: dns.name.Name) -> dns.rcode.Rcode | None:
        # All names in the update section must be within the zone (RFC 2136
        # section 3.4.2.1).  This is checked before applying anything so that
        # a bad name cannot leave a partially applied update behind.
        for rrset in self.update:
            if not self._absolute_name(rrset.name).is_subdomain(origin):
                return dns.rcode.NOTZONE
        return None

    def _apply_updates(
        self, txn: dns.transaction.Transaction, origin: dns.name.Name
    ) -> None:
        # RFC 2136 section 3.4.2.
        for rrset in self.update:
            name = self._absolute_name(rrset.name)
            if rrset.deleting == dns.rdataclass.ANY:
                if rrset.rdtype == dns.rdatatype.ANY:
                    self._delete_name(txn, name, origin)
                elif not _is_undeletable(rrset.rdtype, name, origin):
                    # Delete an RRset.
                    txn.delete(name, rrset.rdtype, rrset.covers)
            elif rrset.deleting == dns.rdataclass.NONE:
                if not _is_undeletable(rrset.rdtype, name, origin):
                    # Delete RRs from an RRset.  It is not an error if some
                    # of the RRs do not exist.
                    txn.delete(name, rrset.to_rdataset())
            else:
                self._add_rrset(txn, name, rrset, origin)

    def _delete_name(
        self,
        txn: dns.transaction.Transaction,
        name: dns.name.Name,
        origin: dns.name.Name,
    ) -> None:
        # Delete all RRsets at a name, except that the SOA and NS RRsets at
        # the zone apex are not deleted (RFC 2136 section 3.4.2.5).
        if name == origin:
            node = txn.get_node(name)
            if node is not None:
                for rdataset in list(node.rdatasets):
                    if not _is_undeletable(rdataset.rdtype, name, origin):
                        txn.delete(name, rdataset.rdtype, rdataset.covers)
        else:
            txn.delete(name)

    def _add_rrset(
        self,
        txn: dns.transaction.Transaction,
        name: dns.name.Name,
        rrset: dns.rrset.RRset,
        origin: dns.name.Name,
    ) -> None:
        # Add RRs to an RRset (RFC 2136 section 3.4.2.2).  Adds that would
        # mix a CNAME with other data, or add an SOA away from the zone
        # apex, are ignored.
        if rrset.rdtype == dns.rdatatype.SOA and name != origin:
            return
        node = txn.get_node(name)
        if node is not None:
            kinds = {
                dns.node.NodeKind.classify_rdataset(rdataset)
                for rdataset in node.rdatasets
            }
            if rrset.rdtype == dns.rdatatype.CNAME:
                if dns.node.NodeKind.REGULAR in kinds:
                    return
            elif (
                dns.node.NodeKind.classify(rrset.rdtype, rrset.covers)
                == dns.node.NodeKind.REGULAR
                and dns.node.NodeKind.CNAME in kinds
            ):
                return
        txn.add(name, rrset.to_rdataset())

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

### BEGIN generated UpdateSection constants

ZONE = UpdateSection.ZONE
PREREQ = UpdateSection.PREREQ
UPDATE = UpdateSection.UPDATE
ADDITIONAL = UpdateSection.ADDITIONAL

### END generated UpdateSection constants
