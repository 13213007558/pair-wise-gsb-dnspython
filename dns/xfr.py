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

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

import dns.edns
import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataset
import dns.rdatatype
import dns.rdtypes
import dns.rdtypes.ANY
import dns.rdtypes.ANY.SOA
import dns.serial
import dns.transaction
import dns.tsig


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


class TSIGPolicyError(dns.exception.FormError):
    """A zone transfer violated the RFC 8945 TSIG signing policy.

    This is raised when the first or last message of a transfer is not
    signed, or when more than the permitted number of consecutive messages
    arrive without a TSIG.  The in-progress transaction is rolled back and
    nothing is committed to the zone.
    """


class TransferIncomplete(dns.exception.FormError):
    """The transfer ended before a complete, authenticated zone was seen."""


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
        commit_check: Callable[[dns.message.Message], None] | None = None,
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

        :param commit_check: If not ``None``, call this with the message that
            completes the transfer immediately before committing the writer
            transaction.  If it raises, the transaction is rolled back instead
            of committed.  This is the hook that binds authentication to the
            commit, so unauthenticated data can never become visible.
        :type commit_check: None or callable
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
        self.commit_check = commit_check

    def _check_tsig(self, message: dns.message.Message) -> None:
        # RFC 8945 section 5.3.1 lets the messages in the middle of a signed
        # transfer be unsigned, as the next TSIG covers them, but the first and
        # the last message must have a TSIG.  This has to be checked before the
        # transaction is committed, or unauthenticated data ends up in the zone.
        if message.request_mac and not message.had_tsig:
            raise TSIGPolicyError("missing TSIG")

    def process_message(self, message: dns.message.Message) -> bool:
        """Process one message in the transfer.

        The message should have the same relativization as was specified when
        the `dns.xfr.Inbound` was created.  The message should also have been
        created with `one_rr_per_rrset=True` because order matters.

        If the request was TSIG-signed, i.e. the message was parsed with a
        nonempty *request_mac*, then the first and the last message of the
        transfer must have a TSIG, and nothing is committed otherwise.

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
            self._check_tsig(message)
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
                    self._check_tsig(message)
                    if self.commit_check is not None:
                        # Run the authentication gate before anything becomes
                        # visible; a failure rolls the transfer back.
                        try:
                            self.commit_check(message)
                        except Exception:
                            self.txn.rollback()
                            self.txn = None
                            raise
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


@dataclass(frozen=True)
class XfrResult:
    """The outcome of a successfully authenticated zone transfer.

    :ivar serial: The SOA serial number of the zone that was committed.
    :type serial: int
    :ivar message_count: The total number of DNS messages consumed from the
        transfer.
    :type message_count: int
    :ivar authenticated_count: The number of those messages that carried a
        cryptographically valid TSIG.
    :type authenticated_count: int
    """

    serial: int
    message_count: int
    authenticated_count: int


# RFC 8945 section 5.3.1 requires the first and last messages of a
# multi-message transfer to be TSIG-signed; the messages in between may be
# unsigned because the following TSIG covers them through the ongoing digest
# context.  It does not define a hard bound, so we cap the run of consecutive
# unsigned messages to keep a tampered or stalled stream from being digested
# without limit.
DEFAULT_MAX_UNSIGNED_MESSAGES = 100


class AuthenticatedInbound:
    """An inbound zone transfer bound to TSIG verification.

    This is the secure entry point for importing raw DNS messages received
    over a custom transport.  Unlike :py:class:`dns.xfr.Inbound`, which trusts
    the parsed :py:attr:`dns.message.Message.had_tsig` attribute, this class
    parses each wire message itself with the configured keyring and maintains
    the continuous RFC 8945 TSIG digest context.  Authentication therefore
    cannot be forged by setting ``had_tsig`` on a message object.

    The first and the last message of the transfer must carry a valid TSIG,
    and only a bounded number of consecutive messages in between may be
    unsigned.  Any insertion, deletion, reordering, or truncation invalidates
    the running MAC, so the transfer fails before anything is committed.

    The underlying :py:class:`dns.xfr.Inbound` transaction is only committed
    once the transfer is both semantically complete and fully authenticated;
    every other outcome (EOF, cancellation, a bad MAC, a bad SOA, or an IXFR
    serial problem) rolls the transaction back and leaves the previously
    visible zone untouched.
    """

    def __init__(
        self,
        txn_manager: dns.transaction.TransactionManager,
        keyring: Any,
        request_mac: bytes,
        rdtype: dns.rdatatype.RdataType = dns.rdatatype.AXFR,
        serial: int | None = None,
        is_udp: bool = False,
        raise_on_serial_went_backwards: bool = True,
        max_unsigned_messages: int = DEFAULT_MAX_UNSIGNED_MESSAGES,
        transaction_setup: Callable[[dns.transaction.Transaction], None] | None = None,
    ):
        """Initialize an authenticated inbound zone transfer.

        :param txn_manager: A :py:class:`dns.transaction.TransactionManager`,
            typically a :py:class:`dns.zone.Zone`.
        :param keyring: The TSIG key, keyring, or keyring callable used to
            verify every signed message.  See :py:func:`dns.message.from_wire`.
        :param request_mac: The MAC of the TSIG-signed transfer request.  This
            must be nonempty; it anchors the ongoing digest so that an attacker
            cannot start a forged transfer.
        :type request_mac: bytes
        :param rdtype: ``dns.rdatatype.AXFR`` or ``dns.rdatatype.IXFR``.
        :param serial: The base serial for an IXFR; required for IXFR.
        :param is_udp: Whether UDP is the transport for this transfer.
        :type is_udp: bool
        :param raise_on_serial_went_backwards: Whether to raise if an IXFR
            offers a serial older than the current one.
        :param max_unsigned_messages: The maximum number of consecutive
            unsigned messages permitted in the middle of the transfer.
        :type max_unsigned_messages: int
        :param transaction_setup: Optional callable invoked with each writer
            transaction before it is used.
        """
        if not isinstance(request_mac, bytes | bytearray) or len(request_mac) == 0:
            raise ValueError(
                "a nonempty request_mac is required for an authenticated transfer"
            )
        if max_unsigned_messages < 0:
            raise ValueError("max_unsigned_messages must not be negative")
        self.keyring = keyring
        self.request_mac = bytes(request_mac)
        self.max_unsigned_messages = max_unsigned_messages
        # Only TCP-style multi-message transfers can have unsigned middle
        # messages; a UDP transfer is a single message that must be signed.
        self._multi = not is_udp
        self.inbound = Inbound(
            txn_manager,
            rdtype,
            serial,
            is_udp,
            raise_on_serial_went_backwards,
            transaction_setup,
            commit_check=self._commit_check,
        )
        self.origin = self.inbound.origin
        # from_wire() relativizes names against this (absolute, or None when
        # the manager does not relativize), mirroring dns.query's transfers.
        self.wire_origin = txn_manager.from_wire_origin()
        self._tsig_ctx: dns.tsig.HMACTSig | dns.tsig.GSSTSig | None = None
        self._message_count = 0
        self._authenticated_count = 0
        self._unsigned_run = 0
        self._finalized = False

    @property
    def message_count(self) -> int:
        """The number of messages consumed so far."""
        return self._message_count

    @property
    def authenticated_count(self) -> int:
        """The number of messages with a valid TSIG seen so far."""
        return self._authenticated_count

    def _fail(self, exc: Exception) -> None:
        # Mark the transfer dead and roll the underlying transaction back so
        # the previously visible zone is left unchanged.
        self._finalized = True
        if self.inbound.txn is not None:
            self.inbound.txn.rollback()
            self.inbound.txn = None
        raise exc

    def _commit_check(self, message: dns.message.Message) -> None:
        # This runs inside Inbound.process_message() on the final message,
        # before the writer transaction is committed, so a failure prevents
        # the new zone from ever becoming visible.
        if not message.had_tsig:
            raise TSIGPolicyError("last transfer message is not TSIG-signed")
        if self._authenticated_count == 0:
            raise TSIGPolicyError("transfer contained no TSIG")

    def process_wire(self, wire: bytes) -> bool:
        """Parse, verify, and process one raw DNS message of the transfer.

        :param wire: One complete, unframed DNS message in wire format (for
            TCP this is the message without the two-octet length prefix).
        :type wire: bytes
        :returns: ``True`` if the transfer is complete and committed, and
            ``False`` if more messages are expected.
        :raises: A :py:class:`dns.exception.DNSException` subclass on any
            verification or transfer error; the transaction is rolled back.
        """
        if self._finalized:
            raise TSIGPolicyError("transfer has already ended")
        try:
            message = dns.message.from_wire(
                wire,
                keyring=self.keyring,
                request_mac=self.request_mac,
                xfr=True,
                origin=self.wire_origin,
                tsig_ctx=self._tsig_ctx,
                multi=self._multi,
                one_rr_per_rrset=self.inbound.incremental,
            )
        except dns.exception.DNSException as exc:
            # A bad MAC, unknown key, malformed TSIG, or structural parse
            # failure means this stream cannot be authenticated.
            self._fail(exc)
        self._tsig_ctx = message.tsig_ctx
        self._message_count += 1
        if message.had_tsig:
            # from_wire() already validated the MAC against the ongoing
            # context, so reaching here means this message is authentic.
            self._authenticated_count += 1
            self._unsigned_run = 0
        else:
            self._unsigned_run += 1
            if self._message_count == 1:
                # RFC 8945 5.3.1: the first message must be signed.
                self._fail(TSIGPolicyError("first transfer message is not TSIG-signed"))
            if self._unsigned_run > self.max_unsigned_messages:
                self._fail(
                    TSIGPolicyError("too many consecutive unsigned transfer messages")
                )
        try:
            done = self.inbound.process_message(message)
        except dns.exception.DNSException as exc:
            self._fail(exc)
        if done:
            # The pre-commit gate above has already verified the final TSIG,
            # and Inbound has committed the now fully authenticated transfer.
            self._finalized = True
        return done

    def finish(self) -> XfrResult:
        """Signal that no more messages will arrive and return the result.

        :raises dns.xfr.TransferIncomplete: If the transfer never reached its
            final SOA, or the final message was not TSIG-signed.
        """
        if not self.inbound.done or not self._finalized:
            self._fail(TransferIncomplete("transfer ended before completion"))
        assert self.inbound.soa_rdataset is not None
        soa = cast(dns.rdtypes.ANY.SOA.SOA, self.inbound.soa_rdataset[0])
        return XfrResult(
            serial=soa.serial,
            message_count=self._message_count,
            authenticated_count=self._authenticated_count,
        )

    def cancel(self) -> None:
        """Abandon the transfer and roll back any uncommitted changes."""
        self._fail(TransferIncomplete("transfer cancelled"))

    def __enter__(self) -> "AuthenticatedInbound":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.inbound.txn is not None:
            self.inbound.txn.rollback()
            self.inbound.txn = None
        self._finalized = True
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
