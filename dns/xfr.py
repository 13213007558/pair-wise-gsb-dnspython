# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2017 Nominum, Inc.
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

from collections.abc import Callable, Iterator, Sequence
from typing import TYPE_CHECKING, Any, cast

import dns.edns
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataset
import dns.rdatatype
import dns.rdtypes
import dns.rdtypes.ANY
import dns.rdtypes.ANY.SOA
import dns.rrset
import dns.serial
import dns.transaction
import dns.tsig

if TYPE_CHECKING:
    import dns.zone


class TransferError(dns.exception.DNSException):
    """A zone transfer response got a non-zero rcode."""

    def __init__(self, rcode):
        message = f"Zone transfer error: {dns.rcode.to_text(rcode)}"
        super().__init__(message)
        self.rcode = rcode


class SerialWentBackwards(dns.exception.FormError):
    """The current serial number is less than the serial we know."""


class UseTCP(dns.exception.DNSException):
    """This IXFR cannot be completed with UDP."""


class Inbound:
    """
    State machine for zone transfers.
    """

    def __init__(
        self,
        txn_manager: dns.transaction.TransactionManager,
        rdtype: dns.rdatatype.RdataType = dns.rdatatype.AXFR,
        serial: int | None = None,
        is_udp: bool = False,
        raise_on_serial_went_backwards: bool = True,
        transaction_setup: Callable[[dns.transaction.Transaction], None] | None = None,
    ):
        """Initialize an inbound zone transfer.

        *txn_manager* is a :py:class:`dns.transaction.TransactionManager`.

        *rdtype* can be `dns.rdatatype.AXFR` or `dns.rdatatype.IXFR`

        *serial* is the base serial number for IXFRs, and is required in
        that case.

        :param is_udp: Whether UDP is being used for this XFR.
        :type is_udp: bool

        :param transaction_setup: If not ``None``, call the object's setup()
            method with the just-created writer transaction.  This lets the caller
            alter the transaction's configuration before it is used, for example adding
            checking policies.
        :type transaction_setup: None or dns.transaction.TransactionSetup
        """
        self.txn_manager = txn_manager
        self.txn: dns.transaction.Transaction | None = None
        self.rdtype = rdtype
        if rdtype == dns.rdatatype.IXFR:
            if serial is None:
                raise ValueError("a starting serial must be supplied for IXFRs")
            self.incremental = True
        elif rdtype == dns.rdatatype.AXFR:
            if is_udp:
                raise ValueError("is_udp specified for AXFR")
            self.incremental = False
        else:
            raise ValueError("rdtype is not IXFR or AXFR")
        self.serial = serial
        self.is_udp = is_udp
        _, _, origin = txn_manager.origin_information()
        if origin is None:
            raise ValueError("transaction manager must supply an origin for XFRs")
        self.origin = origin
        self.soa_rdataset: dns.rdataset.Rdataset | None = None
        self.done = False
        self.expecting_SOA = False
        self.delete_mode = False
        self.raise_on_serial_went_backwards = raise_on_serial_went_backwards
        self.transaction_setup = transaction_setup

    def process_message(self, message: dns.message.Message) -> bool:
        """Process one message in the transfer.

        The message should have the same relativization as was specified when
        the `dns.xfr.Inbound` was created.  The message should also have been
        created with `one_rr_per_rrset=True` because order matters.

        Returns `True` if the transfer is complete, and `False` otherwise.
        """
        if self.txn is None:
            self.txn = self.txn_manager.writer(not self.incremental)
            if self.transaction_setup is not None:
                self.transaction_setup(self.txn)
        rcode = message.rcode()
        if rcode != dns.rcode.NOERROR:
            raise TransferError(rcode)
        #
        # We don't require a question section, but if it is present is
        # should be correct.
        #
        if len(message.question) > 0:
            if message.question[0].name != self.origin:
                raise dns.exception.FormError("wrong question name")
            if message.question[0].rdtype != self.rdtype:
                raise dns.exception.FormError("wrong question rdatatype")
        answer_index = 0
        if self.soa_rdataset is None:
            #
            # This is the first message.  We're expecting an SOA at
            # the origin.
            #
            if not message.answer or message.answer[0].name != self.origin:
                raise dns.exception.FormError("No answer or RRset not for zone origin")
            rrset = message.answer[0]
            rdataset = rrset
            if rdataset.rdtype != dns.rdatatype.SOA:
                raise dns.exception.FormError("first RRset is not an SOA")
            answer_index = 1
            self.soa_rdataset = rdataset.copy()  # pyright: ignore
            if self.incremental:
                assert self.soa_rdataset is not None
                soa = cast(dns.rdtypes.ANY.SOA.SOA, self.soa_rdataset[0])
                if soa.serial == self.serial:
                    #
                    # We're already up-to-date.
                    #
                    self.done = True
                elif dns.serial.Serial(soa.serial) < self.serial:
                    # It went backwards!
                    if self.raise_on_serial_went_backwards:
                        raise SerialWentBackwards
                    self.done = True
                else:
                    if self.is_udp and len(message.answer[answer_index:]) == 0:
                        #
                        # There are no more records, so this is the
                        # "truncated" response.  Say to use TCP
                        #
                        raise UseTCP
                    #
                    # Note we're expecting another SOA so we can detect
                    # if this IXFR response is an AXFR-style response.
                    #
                    self.expecting_SOA = True
        #
        # Process the answer section (other than the initial SOA in
        # the first message).
        #
        for rrset in message.answer[answer_index:]:
            name = rrset.name
            rdataset = rrset
            if self.done:
                raise dns.exception.FormError("answers after final SOA")
            assert self.txn is not None  # for mypy
            if rdataset.rdtype == dns.rdatatype.SOA and name == self.origin:
                #
                # Every time we see an origin SOA delete_mode inverts
                #
                if self.incremental:
                    self.delete_mode = not self.delete_mode
                #
                # If this SOA Rdataset is equal to the first we saw
                # then we're finished. If this is an IXFR we also
                # check that we're seeing the record in the expected
                # part of the response.
                #
                if rdataset == self.soa_rdataset and (
                    (not self.incremental) or self.delete_mode
                ):
                    #
                    # This is the final SOA
                    #
                    soa = cast(dns.rdtypes.ANY.SOA.SOA, rdataset[0])
                    if self.expecting_SOA:
                        # We got an empty IXFR sequence!
                        raise dns.exception.FormError("empty IXFR sequence")
                    if self.incremental and self.serial != soa.serial:
                        raise dns.exception.FormError("unexpected end of IXFR sequence")
                    self.txn.replace(name, rdataset)
                    self.txn.commit()
                    self.txn = None
                    self.done = True
                else:
                    #
                    # This is not the final SOA
                    #
                    self.expecting_SOA = False
                    soa = cast(dns.rdtypes.ANY.SOA.SOA, rdataset[0])
                    if self.incremental:
                        if self.delete_mode:
                            # This is the start of an IXFR deletion set
                            if soa.serial != self.serial:
                                raise dns.exception.FormError(
                                    "IXFR base serial mismatch"
                                )
                        else:
                            # This is the start of an IXFR addition set
                            self.serial = soa.serial
                            self.txn.replace(name, rdataset)
                    else:
                        # We saw a non-final SOA for the origin in an AXFR.
                        raise dns.exception.FormError("unexpected origin SOA in AXFR")
                continue
            if self.expecting_SOA:
                #
                # We made an IXFR request and are expecting another
                # SOA RR, but saw something else, so this must be an
                # AXFR response.
                #
                self.incremental = False
                self.expecting_SOA = False
                self.delete_mode = False
                self.txn.rollback()
                self.txn = self.txn_manager.writer(True)
                if self.transaction_setup is not None:
                    self.transaction_setup(self.txn)
                #
                # Note we are falling through into the code below
                # so whatever rdataset this was gets written.
                #
            # Ignore glue that is not a subdomain of the origin.  For pathological
            # cases it would be good if we could keep it in some side location, but
            # dnspython zones don't have a place or an API for that, so we just ignore
            # it at this time.
            if not name.is_subdomain(self.origin):
                continue
            # Add or remove the data
            if self.delete_mode:
                self.txn.delete_exact(name, rdataset)
            else:
                self.txn.add(name, rdataset)
        if self.is_udp and not self.done:
            #
            # This is a UDP IXFR and we didn't get to done, and we didn't
            # get the proper "truncated" response
            #
            raise dns.exception.FormError("unexpected end of UDP IXFR")
        return self.done

    #
    # Inbounds are context managers.
    #

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.txn:
            self.txn.rollback()
        return False


def make_query(
    txn_manager: dns.transaction.TransactionManager,
    serial: int | None = 0,
    use_edns: int | bool | None = None,
    ednsflags: int | None = None,
    payload: int | None = None,
    request_payload: int | None = None,
    options: list[dns.edns.Option] | None = None,
    keyring: Any = None,
    keyname: dns.name.Name | None = None,
    keyalgorithm: dns.name.Name | str = dns.tsig.default_algorithm,
) -> tuple[dns.message.QueryMessage, int | None]:
    """Make an AXFR or IXFR query.

    :param txn_manager: The transaction manager for this transfer, typically
        a :py:class:`dns.zone.Zone`.
    :type txn_manager: :py:class:`dns.transaction.TransactionManager`
    :param serial: If ``0``, IXFR is attempted using the most recent serial
        from *txn_manager* (caller must ensure no write transactions are
        active that could invalidate the retrieved serial).  If a serial
        cannot be determined, AXFR is forced.  Other integer values are the
        starting serial to use.  ``None`` forces an AXFR.
    :type serial: int or ``None``

    Please see the documentation for :py:func:`dns.message.make_query` and
    :py:func:`dns.message.Message.use_tsig` for details on the other parameters
    to this function.

    :returns: A ``(query, serial)`` tuple.
    :rtype: tuple
    """
    zone_origin, _, origin = txn_manager.origin_information()
    if zone_origin is None:
        raise ValueError("no zone origin")
    if serial is None:
        rdtype = dns.rdatatype.AXFR
    elif not isinstance(serial, int):
        raise ValueError("serial is not an integer")
    elif serial == 0:
        with txn_manager.reader() as txn:
            rdataset = txn.get(origin, "SOA")
            if rdataset:
                soa = cast(dns.rdtypes.ANY.SOA.SOA, rdataset[0])
                serial = soa.serial
                rdtype = dns.rdatatype.IXFR
            else:
                serial = None
                rdtype = dns.rdatatype.AXFR
    elif serial > 0 and serial < 4294967296:
        rdtype = dns.rdatatype.IXFR
    else:
        raise ValueError("serial out-of-range")
    rdclass = txn_manager.get_class()
    q = dns.message.make_query(
        zone_origin,
        rdtype,
        rdclass,
        use_edns,
        False,
        ednsflags,
        payload,
        request_payload,
        options,
    )
    if serial is not None:
        rdata = dns.rdata.from_text(rdclass, "SOA", f". . {serial} 0 0 0 0")
        rrset = q.find_rrset(
            q.authority, zone_origin, rdclass, dns.rdatatype.SOA, create=True
        )
        rrset.add(rdata, 0)
    if keyring is not None:
        q.use_tsig(keyring, keyname, algorithm=keyalgorithm)
    return (q, serial)


def extract_serial_from_query(query: dns.message.Message) -> int | None:
    """Extract the SOA serial number from query if it is an IXFR and return
    it, otherwise return None.

    *query* is a dns.message.QueryMessage that is an IXFR or AXFR request.

    Raises if the query is not an IXFR or AXFR, or if an IXFR doesn't have
    an appropriate SOA RRset in the authority section.
    """
    if not isinstance(query, dns.message.QueryMessage):
        raise ValueError("query not a QueryMessage")
    question = query.question[0]
    if question.rdtype == dns.rdatatype.AXFR:
        return None
    elif question.rdtype != dns.rdatatype.IXFR:
        raise ValueError("query is not an AXFR or IXFR")
    soa_rrset = query.find_rrset(
        query.authority, question.name, question.rdclass, dns.rdatatype.SOA
    )
    soa = cast(dns.rdtypes.ANY.SOA.SOA, soa_rrset[0])
    return soa.serial


class UndefinedSerialOrder(dns.exception.DNSException):
    """The order of two serial numbers is undefined (RFC 1982)."""


class IXFRHistoryUnavailable(dns.exception.DNSException):
    """The history needed to generate an IXFR is not available."""


# A snapshot of the contents of a zone (or zone version), mapping
# absolute owner names to a map of (rdtype, covers) to rdataset.
_SnapshotKey = tuple[dns.rdatatype.RdataType, dns.rdatatype.RdataType]
_Snapshot = dict[dns.name.Name, dict[_SnapshotKey, dns.rdataset.Rdataset]]

_SOA_KEY: _SnapshotKey = (dns.rdatatype.SOA, dns.rdatatype.NONE)


def _snapshot_zone(
    source: "dns.transaction.Transaction | dns.zone.Zone",
) -> tuple[dns.name.Name, _Snapshot]:
    """Read *source*, which may be a transaction or a zone, into a
    snapshot of its contents, returning an (origin, snapshot) tuple.

    The source is only read, never modified.
    """
    if isinstance(source, dns.transaction.Transaction):
        manager = source.manager
    else:
        manager = source
    origin, _, _ = manager.origin_information()
    if origin is None:
        raise ValueError("zone source does not have an origin")
    snapshot: _Snapshot = {}
    for name, rdataset in source.iterate_rdatasets():
        if not name.is_absolute():
            name = name.derelativize(origin)
        key = (rdataset.rdtype, rdataset.covers)
        snapshot.setdefault(name, {})[key] = rdataset
    return (origin, snapshot)


def _snapshot_soa(origin: dns.name.Name, snapshot: _Snapshot) -> dns.rdataset.Rdataset:
    """Get the SOA rdataset from a snapshot."""
    node = snapshot.get(origin)
    if node is not None:
        rdataset = node.get(_SOA_KEY)
        if rdataset is not None:
            return rdataset
    raise ValueError("zone source has no SOA at the origin")


def _diff_snapshots(origin: dns.name.Name, old: _Snapshot, new: _Snapshot) -> tuple[
    list[tuple[dns.name.Name, dns.rdataset.Rdataset]],
    list[tuple[dns.name.Name, dns.rdataset.Rdataset]],
]:
    """Compute the deletions and additions that transform *old* into *new*.

    The SOA rdataset at the origin is excluded, as it is conveyed by the
    IXFR sequence boundaries.  TTL-only changes are treated as changes.
    """
    deletions: list[tuple[dns.name.Name, dns.rdataset.Rdataset]] = []
    additions: list[tuple[dns.name.Name, dns.rdataset.Rdataset]] = []
    for name in sorted(set(old) | set(new)):
        old_node = old.get(name, {})
        new_node = new.get(name, {})
        for key in sorted(old_node):
            if name == origin and key == _SOA_KEY:
                continue
            old_rdataset = old_node[key]
            new_rdataset = new_node.get(key)
            if new_rdataset is None:
                deletions.append((name, old_rdataset))
            elif old_rdataset != new_rdataset or old_rdataset.ttl != new_rdataset.ttl:
                deletions.append((name, old_rdataset))
                additions.append((name, new_rdataset))
        for key in sorted(new_node):
            if name == origin and key == _SOA_KEY:
                continue
            if key not in old_node:
                additions.append((name, new_node[key]))
    return (deletions, additions)


class Outbound:
    """Generator for outbound zone transfers.

    This is the server side of a zone transfer: given the client's query,
    the current contents of the zone, and (for IXFRs) the consecutive
    historical versions of the zone reaching back to the client's version,
    iterating over it yields the sequence of response messages to send to
    the client.  The messages are ready to be encoded with
    :py:meth:`dns.message.Message.to_wire`.
    """

    def __init__(
        self,
        query: dns.message.QueryMessage,
        current: "dns.transaction.Transaction | dns.zone.Zone",
        history: Sequence["dns.transaction.Transaction | dns.zone.Zone"] = (),
        *,
        fallback_to_axfr: bool = False,
        max_size: int = 65535,
    ):
        """Initialize an outbound zone transfer.

        :param query: The client's AXFR or IXFR query.  For an IXFR, the
            client's SOA serial number is extracted from the query's
            authority section.
        :type query: dns.message.QueryMessage
        :param current: The current contents of the zone, either a
            :py:class:`dns.transaction.Transaction` or a
            :py:class:`dns.zone.Zone`.  It is only read, never modified.
        :param history: The consecutive historical versions of the zone,
            oldest first, needed to serve an IXFR.  The first version must
            be the version the client has, i.e. its SOA serial must be the
            serial from the query, and the versions must have strictly
            increasing serial numbers (in the RFC 1982 sense) leading up to
            the current version.  Each version is only read, never modified.
        :param fallback_to_axfr: If True, respond with an AXFR-style full
            transfer when the history needed for an IXFR is not available
            (e.g. it has been pruned or is not consecutive).  If False,
            raise :py:exc:`dns.xfr.IXFRHistoryUnavailable` instead.
        :type fallback_to_axfr: bool
        :param max_size: The maximum wire format size of any generated
            message.  Compression, EDNS, and TSIG (including continuous
            signing of a multi-message transfer) are all accounted for when
            packing messages.  If a single record does not fit, iterating
            raises :py:exc:`dns.exception.TooBig`.
        :type max_size: int

        Iterating over the outbound transfer yields
        :py:class:`dns.message.Message` objects.  Packetization never
        changes the order of the update records.  When encoding the
        messages, the TSIG context should be chained, e.g.::

            tsig_ctx = None
            for message in outbound:
                wire = message.to_wire(multi=True, tsig_ctx=tsig_ctx)
                tsig_ctx = message.tsig_ctx
                ...  # send wire

        :raises dns.xfr.UndefinedSerialOrder: If the client's serial and the
            current serial differ by exactly half of the serial number
            space, so that their order is undefined (RFC 1982).
        :raises dns.xfr.IXFRHistoryUnavailable: If the history needed for
            the IXFR is not available and *fallback_to_axfr* is False.
        :raises ValueError: If the query is not an AXFR or IXFR query, if
            its question name is not the zone origin, or if a zone source
            has no origin or SOA.
        """
        if len(query.question) == 0:
            raise ValueError("query has no question section")
        serial = extract_serial_from_query(query)
        self.query = query
        self.max_size = max_size
        self.origin, current_snapshot = _snapshot_zone(current)
        if query.question[0].name != self.origin:
            raise ValueError("query question name is not the zone origin")
        self.current_soa = _snapshot_soa(self.origin, current_snapshot)
        self._items: list[tuple[dns.name.Name, dns.rdataset.Rdataset]] = []
        if serial is None:
            self._make_axfr(current_snapshot)
        else:
            self._make_ixfr(serial, current_snapshot, history, fallback_to_axfr)

    def _make_axfr(self, current_snapshot: _Snapshot) -> None:
        """Build a full zone transfer sequence."""
        items = self._items
        items.append((self.origin, self.current_soa))
        for name in sorted(current_snapshot):
            node = current_snapshot[name]
            for key in sorted(node):
                if name == self.origin and key == _SOA_KEY:
                    continue
                items.append((name, node[key]))
        items.append((self.origin, self.current_soa))

    def _make_ixfr(
        self,
        serial: int,
        current_snapshot: _Snapshot,
        history: Sequence["dns.transaction.Transaction | dns.zone.Zone"],
        fallback_to_axfr: bool,
    ) -> None:
        """Build an incremental transfer sequence per RFC 1995."""
        current_serial = cast(dns.rdtypes.ANY.SOA.SOA, self.current_soa[0]).serial
        client_serial = dns.serial.Serial(serial)
        if client_serial == current_serial or client_serial > current_serial:
            #
            # The client is already up-to-date (or is ahead of us, in
            # which case we have nothing useful to send either), so we
            # respond with just the current SOA.
            #
            self._items.append((self.origin, self.current_soa))
            return
        if not client_serial < current_serial:
            #
            # The serials differ but neither is less than the other, so
            # they are exactly half of the serial number space apart and
            # their order is undefined (RFC 1982).
            #
            raise UndefinedSerialOrder(
                f"cannot determine the order of serials {serial} "
                f"and {current_serial}"
            )
        #
        # Snapshot the history and check that it is a consecutive chain of
        # versions from the client's serial to the current serial.
        #
        versions: list[tuple[dns.rdataset.Rdataset, _Snapshot]] = []
        for source in history:
            origin, snapshot = _snapshot_zone(source)
            if origin != self.origin:
                raise ValueError("history version has a different origin")
            versions.append((_snapshot_soa(origin, snapshot), snapshot))
        versions.append((self.current_soa, current_snapshot))
        usable = len(versions) >= 2 and self._serial(versions[0][0]) == serial
        if usable:
            for i in range(len(versions) - 1):
                if not self._serial(versions[i][0]) < self._serial(versions[i + 1][0]):
                    usable = False
                    break
        if not usable:
            if not fallback_to_axfr:
                raise IXFRHistoryUnavailable(
                    f"no consecutive version history from serial {serial} "
                    f"to {current_serial}"
                )
            self._make_axfr(current_snapshot)
            return
        #
        # Emit the RFC 1995 sequence: the current SOA, then for each
        # version step the old SOA, the deletions, the new SOA, and the
        # additions, and finally the current SOA again as the end marker.
        #
        items = self._items
        items.append((self.origin, self.current_soa))
        for i in range(len(versions) - 1):
            old_soa, old_snapshot = versions[i]
            new_soa, new_snapshot = versions[i + 1]
            deletions, additions = _diff_snapshots(
                self.origin, old_snapshot, new_snapshot
            )
            items.append((self.origin, old_soa))
            items.extend(deletions)
            items.append((self.origin, new_soa))
            items.extend(additions)
        items.append((self.origin, self.current_soa))

    @staticmethod
    def _serial(soa: dns.rdataset.Rdataset) -> dns.serial.Serial:
        return dns.serial.Serial(cast(dns.rdtypes.ANY.SOA.SOA, soa[0]).serial)

    def _make_message(self, first: bool) -> dns.message.Message:
        """Make a response message skeleton."""
        if first:
            response = dns.message.make_response(self.query)
        else:
            response = dns.message.make_response(
                self.query, copy_mode=dns.message.CopyMode.NOTHING
            )
        response.flags |= dns.flags.AA
        response.origin = self.origin
        return response

    def __iter__(self) -> Iterator[dns.message.Message]:
        """Generate the response messages for the transfer."""
        tsig_ctx = None
        message = self._make_message(True)
        answers = 0
        for name, rdataset in self._items:
            rrset = dns.rrset.RRset(
                name, rdataset.rdclass, rdataset.rdtype, rdataset.covers
            )
            rrset.update(rdataset)
            while True:
                message.answer.append(rrset)
                try:
                    message.to_wire(
                        max_size=self.max_size, multi=True, tsig_ctx=tsig_ctx
                    )
                except dns.exception.TooBig:
                    message.answer.pop()
                    if answers == 0:
                        # A single record doesn't fit in a message.
                        raise
                    tsig_ctx = message.tsig_ctx
                    yield message
                    message = self._make_message(False)
                    answers = 0
                    continue
                answers += 1
                break
        if answers > 0:
            yield message
