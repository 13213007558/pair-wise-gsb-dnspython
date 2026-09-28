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
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
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

### BEGIN generated UpdateSection constants

ZONE = UpdateSection.ZONE
PREREQ = UpdateSection.PREREQ
UPDATE = UpdateSection.UPDATE
ADDITIONAL = UpdateSection.ADDITIONAL

### END generated UpdateSection constants


# Metatypes that may not be added to or deleted from a zone by a dynamic
# update (RFC 2136 3.4.2).
_no_update_types = frozenset(
    [
        dns.rdatatype.NONE,
        dns.rdatatype.IXFR,
        dns.rdatatype.AXFR,
        dns.rdatatype.MAILB,
        dns.rdatatype.MAILA,
        dns.rdatatype.ANY,
    ]
)


class _UpdateApplier:
    """Stateful helper for apply(), holding the zone-derived context."""

    def __init__(
        self,
        update: UpdateMessage,
        msg_origin: dns.name.Name,
        manager: dns.transaction.TransactionManager,
    ) -> None:
        absolute_origin, relativize, _ = manager.origin_information()
        assert absolute_origin is not None
        self.update = update
        self.msg_origin = msg_origin
        self.manager = manager
        self.zclass = manager.get_class()
        self.origin = absolute_origin
        self.relativize = relativize
        if relativize:
            self.apex = dns.name.empty
        else:
            self.apex = absolute_origin
        self.soa_serial_updated = False

    def _convert_name(self, name: dns.name.Name) -> dns.name.Name | None:
        """Make *name* absolute and in the manager's relativization format,
        or return ``None`` if it is not in the zone."""
        name = name.derelativize(self.msg_origin)
        if not name.is_subdomain(self.origin):
            return None
        if self.relativize:
            name = name.relativize(self.origin)
        return name

    @staticmethod
    def _effective_class(rrset: dns.rrset.RRset) -> dns.rdataclass.RdataClass:
        # The class of an update or prerequisite RRset as it appeared on
        # the wire.  When a message is parsed, metaclasses (ANY and NONE)
        # are recorded in the rrset's "deleting" attribute and the rrset's
        # class is the zone class; when a message is built with the
        # convenience methods, the metaclass may be the rrset's class
        # instead.
        if rrset.deleting is not None:
            return rrset.deleting
        return rrset.rdclass

    def _check_prerequisites(
        self, txn: dns.transaction.Transaction
    ) -> dns.rcode.Rcode:
        # RFC 2136 3.2.  Value-dependent prerequisites are accumulated
        # into temporary rrsets which must match the zone's rrsets
        # exactly; TTLs are not compared.
        temp: dict[tuple[dns.name.Name, dns.rdatatype.RdataType], set] = {}
        for rrset in self.update.prerequisite:
            if rrset.ttl != 0:
                return dns.rcode.FORMERR
            name = self._convert_name(rrset.name)
            if name is None:
                return dns.rcode.NOTZONE
            rdclass = self._effective_class(rrset)
            rdtype = rrset.rdtype
            if rdclass == dns.rdataclass.ANY:
                if len(rrset) != 0:
                    return dns.rcode.FORMERR
                if rdtype == dns.rdatatype.ANY:
                    if not txn.name_exists(name):
                        return dns.rcode.NXDOMAIN
                elif txn.get(name, rdtype) is None:
                    return dns.rcode.NXRRSET
            elif rdclass == dns.rdataclass.NONE:
                if len(rrset) != 0:
                    return dns.rcode.FORMERR
                if rdtype == dns.rdatatype.ANY:
                    if txn.name_exists(name):
                        return dns.rcode.YXDOMAIN
                elif txn.get(name, rdtype) is not None:
                    return dns.rcode.YXRRSET
            elif rdclass == self.zclass:
                key = (name, rdtype)
                accumulated = temp.setdefault(key, set())
                accumulated.update(rrset)
            else:
                return dns.rcode.FORMERR
        for (name, rdtype), expected in temp.items():
            rdataset = txn.get(name, rdtype)
            if rdataset is None or set(rdataset) != expected:
                return dns.rcode.NXRRSET
        return dns.rcode.NOERROR

    def _check_update_section(self) -> dns.rcode.Rcode:
        # Validate the update section before changing anything
        # (RFC 2136 3.4.2).
        for rrset in self.update.update:
            name = self._convert_name(rrset.name)
            if name is None:
                return dns.rcode.NOTZONE
            rdclass = self._effective_class(rrset)
            rdtype = rrset.rdtype
            if rdclass == self.zclass:
                # An add.
                if rdtype in _no_update_types:
                    return dns.rcode.FORMERR
            elif rdclass == dns.rdataclass.NONE:
                # A delete of specific RRs; the RRs must be present.
                if rrset.ttl != 0 or len(rrset) == 0:
                    return dns.rcode.FORMERR
                if rdtype in _no_update_types:
                    return dns.rcode.FORMERR
            elif rdclass == dns.rdataclass.ANY:
                # A delete of an RRset or of all RRsets at a name.
                if rrset.ttl != 0 or len(rrset) != 0:
                    return dns.rcode.FORMERR
            else:
                return dns.rcode.FORMERR
        return dns.rcode.NOERROR

    def _delete_protected(self, name: dns.name.Name, rdtype) -> bool:
        # The zone's SOA RR and the NS RRs at the zone apex may not be
        # deleted by a dynamic update (RFC 2136 3.4.2).
        if rdtype == dns.rdatatype.SOA:
            return True
        return bool(rdtype == dns.rdatatype.NS and name == self.apex)

    def _delete_all_rrsets(
        self, txn: dns.transaction.Transaction, name: dns.name.Name
    ) -> None:
        node = txn.get_node(name)
        if node is None:
            return
        deletions = [
            (rdataset.rdtype, rdataset.covers)
            for rdataset in node
            if not self._delete_protected(name, rdataset.rdtype)
        ]
        for rdtype, covers in deletions:
            txn.delete(name, rdtype, covers)

    def _add_rr(
        self,
        txn: dns.transaction.Transaction,
        name: dns.name.Name,
        ttl: int,
        rdtype: dns.rdatatype.RdataType,
        rd: dns.rdata.Rdata,
    ) -> None:
        if rdtype == dns.rdatatype.SOA:
            # The SOA is a singleton at the zone apex; adds elsewhere
            # are ignored, and an add at the apex only replaces the
            # current SOA if its serial is greater in the RFC 1982
            # sense.
            if name != self.apex:
                return
            existing = txn.get(name, dns.rdatatype.SOA)
            if existing is not None and len(existing) > 0:
                new_serial = dns.serial.Serial(rd.serial)  # pyright: ignore
                current_serial = dns.serial.Serial(existing[0].serial)  # pyright: ignore
                if not new_serial > current_serial:
                    return
            txn.replace(name, ttl, rd)
            self.soa_serial_updated = True
            return
        kind = dns.node.NodeKind.classify(rdtype, rd.covers())
        if kind != dns.node.NodeKind.NEUTRAL:
            # CNAMEs may not coexist with other data; adds that would
            # violate this are silently ignored.
            node = txn.get_node(name)
            if node is not None:
                kinds = {
                    dns.node.NodeKind.classify_rdataset(rdataset)
                    for rdataset in node
                }
                if (
                    kind == dns.node.NodeKind.CNAME
                    and dns.node.NodeKind.REGULAR in kinds
                ) or (
                    kind == dns.node.NodeKind.REGULAR
                    and dns.node.NodeKind.CNAME in kinds
                ):
                    return
        txn.add(name, ttl, rd)

    def _apply_updates(self, txn: dns.transaction.Transaction) -> None:
        for rrset in self.update.update:
            name = self._convert_name(rrset.name)
            assert name is not None  # checked by _check_update_section()
            rdclass = self._effective_class(rrset)
            rdtype = rrset.rdtype
            if rdclass == self.zclass:
                for rd in rrset:
                    self._add_rr(txn, name, rrset.ttl, rdtype, rd)
            elif rdclass == dns.rdataclass.NONE:
                if self._delete_protected(name, rdtype):
                    continue
                for rd in rrset:
                    txn.delete(name, rd)
            elif rdclass == dns.rdataclass.ANY:
                if rdtype == dns.rdatatype.ANY:
                    self._delete_all_rrsets(txn, name)
                elif not self._delete_protected(name, rdtype):
                    txn.delete(name, rdtype)

    def apply(self) -> dns.rcode.Rcode:
        txn = self.manager.writer()
        try:
            rcode = self._check_prerequisites(txn)
            if rcode == dns.rcode.NOERROR:
                rcode = self._check_update_section()
            if rcode == dns.rcode.NOERROR:
                self._apply_updates(txn)
                if txn.changed() and not self.soa_serial_updated:
                    # The zone changed and the update did not set the
                    # SOA serial explicitly, so increment it.
                    if txn.get(self.apex, dns.rdatatype.SOA) is not None:
                        txn.update_serial(name=self.apex)
                txn.commit()
            else:
                txn.rollback()
            return rcode
        except BaseException:
            try:
                txn.rollback()
            except dns.transaction.AlreadyEnded:
                pass
            raise


def apply(
    update: UpdateMessage, manager: dns.transaction.TransactionManager
) -> dns.rcode.Rcode:
    """Apply a dynamic update message to a zone, returning an rcode.

    This implements the local (server-side) processing of an RFC 2136
    dynamic update.  The message's prerequisites are checked against the
    current zone content, and if they are all satisfied, the updates are
    applied atomically in a single write transaction obtained from
    *manager* (e.g. a :py:class:`dns.zone.Zone` or
    :py:class:`dns.versioned.Zone`).  If any prerequisite fails, the
    zone is left unchanged.

    The message is assumed to have already been authenticated by the
    caller; no TSIG or policy checks are made.  The message is neither
    modified nor consumed, and may be applied again later; the result
    of each application depends on the state of the zone at that time.

    Owner names are taken literally: wildcard names are not expanded
    and CNAMEs are not followed.  Owner names outside the zone are
    rejected with ``NOTZONE``, format errors with ``FORMERR``, and a
    zone name or class mismatch with ``NOTAUTH``, all before any
    change is made to the zone.

    The RFC 2136 special rules are observed: the SOA and NS rdatasets
    at the zone apex are never deleted; an SOA may only be added at
    the apex, replacing the current SOA only if its serial is greater
    in the RFC 1982 sense; adds that would make a CNAME coexist with
    other data are silently ignored; and the zone's SOA serial is
    incremented if the update changed the zone without explicitly
    setting the serial.

    :param update: the dynamic update message to apply
    :type update: :py:class:`dns.update.UpdateMessage`
    :param manager: the transaction manager for the zone to update
    :type manager: :py:class:`dns.transaction.TransactionManager`
    :rtype: :py:class:`dns.rcode.Rcode`
    """
    if not isinstance(update, UpdateMessage):
        raise TypeError("update must be a dns.update.UpdateMessage")
    if len(update.zone) != 1:
        return dns.rcode.FORMERR
    zone_rrset = update.zone[0]
    if update.origin is not None:
        msg_origin = update.origin
    else:
        # A received message; use the zone section's name.
        msg_origin = zone_rrset.name
    absolute_origin, _, _ = manager.origin_information()
    if absolute_origin is None or msg_origin != absolute_origin:
        return dns.rcode.NOTAUTH
    if zone_rrset.rdclass != manager.get_class():
        return dns.rcode.NOTAUTH
    applier = _UpdateApplier(update, msg_origin, manager)
    return applier.apply()
