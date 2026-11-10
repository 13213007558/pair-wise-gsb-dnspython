# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for dns.xfr.AuthenticatedInbound.

These tests build short, locally generated AXFR/IXFR wire messages and drive
the authenticated inbound state machine directly, so no network or name
server is required.  They focus on the binding between RFC 8945 TSIG
verification and the Inbound transaction: the zone may only be committed when
the transfer is both semantically complete and fully authenticated.
"""

import pytest

import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.transaction
import dns.tsig
import dns.tsigkeyring
import dns.versioned
import dns.xfr
import dns.zone

ORIGIN = dns.name.from_text("example")
KEYRING = dns.tsigkeyring.from_text({"keyname.": "NjHwPsMKjdN++dOfE5iAiQ=="})
KEYNAME = dns.name.from_text("keyname")

AXFR_FIRST = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
example. IN AXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
"""

AXFR_MIDDLE = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;ANSWER
@ 3600 IN NS ns2
"""

AXFR_LAST = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;ANSWER
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
@ 3600 IN SOA foo bar 1 2 3 4 5
"""

AXFR_BASE = """@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
"""

# A single-message AXFR (everything in one message).
AXFR_SINGLE = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
example. IN AXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
ns1 3600 IN A 10.0.0.1
@ 3600 IN SOA foo bar 1 2 3 4 5
"""

IXFR_BASE = """@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
ns1 3600 IN A 10.0.0.1
"""

IXFR = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 2 2 3 4 5
@ 3600 IN SOA foo bar 1 2 3 4 5
ns1 3600 IN A 10.0.0.1
@ 3600 IN SOA foo bar 2 2 3 4 5
ns1 3600 IN A 10.0.0.9
@ 3600 IN SOA foo bar 2 2 3 4 5
"""

IXFR_EXPECTED = """@ 3600 IN SOA foo bar 2 2 3 4 5
@ 3600 IN NS ns1
ns1 3600 IN A 10.0.0.9
"""

# An IXFR whose deletion set claims the wrong base serial.
IXFR_BAD_SERIAL = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN SOA foo bar 2 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN SOA foo bar 4 2 3 4 5
"""


def make_query(zone, rdtype=dns.rdatatype.AXFR, serial=None):
    query, _ = dns.xfr.make_query(zone, serial=serial, keyring=KEYRING, keyname=KEYNAME)
    assert query.question[0].rdtype == rdtype
    query.to_wire()  # populate query.mac
    return query


def render(text, query, signed, tsig_ctx):
    """Render one transfer message, optionally TSIG-signed.

    Returns the (wire, next_context) pair.  For an unsigned message the
    ongoing digest context is folded over its wire bytes, exactly as the
    verifier does, so the following signed message still covers it.
    """
    message = dns.message.from_text(text, origin=ORIGIN, one_rr_per_rrset=True)
    message.id = query.id
    if signed:
        message.use_tsig(KEYRING, KEYNAME)
        message.request_mac = query.mac
        wire = message.to_wire(multi=True, tsig_ctx=tsig_ctx)
        return wire, message.tsig_ctx
    wire = message.to_wire()
    if tsig_ctx is None:
        # An unsigned first message still has to be folded into a context
        # seeded from the request MAC, mirroring the verifier.
        key = dns.tsig.Key(KEYNAME, KEYRING[KEYNAME])
        tsig_ctx = dns.tsig.get_context(key)
        tsig_ctx.update(len(query.mac).to_bytes(2, "big") + query.mac)
    tsig_ctx.update(wire)
    return wire, tsig_ctx


def build_transfer(texts, signed, query):
    """Return the list of wire messages for a transfer.

    *signed* is a sequence of booleans, one per message.
    """
    wires = []
    ctx = None
    for text, is_signed in zip(texts, signed):
        wire, ctx = render(text, query, is_signed, ctx)
        wires.append(wire)
    return wires


def feed(wires, query, zone=None, **kwargs):
    zone = zone or dns.versioned.Zone("example")
    with dns.xfr.AuthenticatedInbound(zone, KEYRING, query.mac, **kwargs) as inbound:
        done = False
        for wire in wires:
            done = inbound.process_wire(wire)
        result = inbound.finish()
    assert done
    return zone, result


def empty_zone():
    return dns.versioned.Zone("example")


def test_axfr_single_message_signed():
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_SINGLE], [True], query)
    zone, result = feed(wires, query)
    assert zone == dns.zone.from_text(
        AXFR_BASE.replace("@ 3600 IN NS ns2\n", "").replace(
            "ns2 3600 IN A 10.0.0.2\n", ""
        ),
        "example",
    )
    assert result.serial == 1
    assert result.message_count == 1
    assert result.authenticated_count == 1


def test_axfr_all_signed_multi_message():
    query = make_query(empty_zone())
    wires = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, True, True], query
    )
    zone, result = feed(wires, query)
    assert zone == dns.zone.from_text(AXFR_BASE, "example")
    assert result.serial == 1
    assert result.message_count == 3
    assert result.authenticated_count == 3


def test_axfr_unsigned_middle_is_allowed():
    query = make_query(empty_zone())
    wires = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, False, True], query
    )
    zone, result = feed(wires, query)
    assert zone == dns.zone.from_text(AXFR_BASE, "example")
    # The middle message is authenticated by the final TSIG even though it
    # carries no TSIG itself.
    assert result.message_count == 3
    assert result.authenticated_count == 2


def test_first_message_unsigned_is_rejected():
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_FIRST, AXFR_LAST], [False, True], query)
    zone = empty_zone()
    with pytest.raises(dns.xfr.TSIGPolicyError):
        feed(wires, query, zone)
    assert zone == empty_zone()


def test_last_message_unsigned_is_rejected_and_rolled_back():
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_FIRST, AXFR_LAST], [True, False], query)
    zone = empty_zone()
    versions = len(zone._versions)
    with pytest.raises(dns.xfr.TSIGPolicyError):
        feed(wires, query, zone)
    # Nothing was committed: no new version and an untouched zone.
    assert len(zone._versions) == versions
    assert zone == empty_zone()


def test_missing_final_signature_eof():
    # The stream simply stops after a signed first message; finish() must fail.
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_FIRST], [True], query)
    zone = empty_zone()
    with dns.xfr.AuthenticatedInbound(zone, KEYRING, query.mac) as inbound:
        assert inbound.process_wire(wires[0]) is False
        with pytest.raises(dns.xfr.TransferIncomplete):
            inbound.finish()
    assert zone == empty_zone()


def test_bad_mac_is_rejected():
    query = make_query(empty_zone())
    wires = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, True, True], query
    )
    corrupted = bytearray(wires[1])
    corrupted[-1] ^= 0xFF
    zone = empty_zone()
    with pytest.raises(dns.exception.DNSException):
        feed([wires[0], bytes(corrupted), wires[2]], query, zone)
    assert zone == empty_zone()


def test_reordering_messages_breaks_authentication():
    query = make_query(empty_zone())
    wires = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, False, True], query
    )
    zone = empty_zone()
    with pytest.raises(dns.tsig.BadSignature):
        feed([wires[0], wires[2], wires[1]], query, zone)
    assert zone == empty_zone()


def test_inserted_message_breaks_authentication():
    query = make_query(empty_zone())
    wires = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, False, True], query
    )
    # Duplicate the unsigned middle message (an insertion).
    zone = empty_zone()
    with pytest.raises(dns.exception.DNSException):
        feed([wires[0], wires[1], wires[1], wires[2]], query, zone)
    assert zone == empty_zone()


def test_truncated_stream_is_rolled_back():
    query = make_query(empty_zone())
    wires = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, False, True], query
    )
    zone = empty_zone()
    with dns.xfr.AuthenticatedInbound(zone, KEYRING, query.mac) as inbound:
        inbound.process_wire(wires[0])
        inbound.process_wire(wires[1])
        with pytest.raises(dns.xfr.TransferIncomplete):
            inbound.finish()
    assert zone == empty_zone()


def test_cancel_rolls_back():
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_FIRST], [True], query)
    zone = empty_zone()
    with dns.xfr.AuthenticatedInbound(zone, KEYRING, query.mac) as inbound:
        inbound.process_wire(wires[0])
        with pytest.raises(dns.xfr.TransferIncomplete):
            inbound.cancel()
        with pytest.raises(dns.xfr.TSIGPolicyError):
            inbound.process_wire(wires[0])
    assert zone == empty_zone()


def test_context_manager_exit_rolls_back():
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_FIRST], [True], query)
    zone = empty_zone()
    with dns.xfr.AuthenticatedInbound(zone, KEYRING, query.mac) as inbound:
        inbound.process_wire(wires[0])
    # Leaving the context without finishing rolls the writer transaction back.
    assert zone == empty_zone()


def test_forged_had_tsig_cannot_authenticate():
    # The entry point only accepts raw wire bytes and performs its own
    # verification, so a hand-built object that claims had_tsig cannot be
    # smuggled in.  A TSIG rendered with a fresh (non-continuing) context
    # fails against the ongoing digest.
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_FIRST, AXFR_LAST], [True, True], query)
    forged = dns.message.from_text(AXFR_LAST, origin=ORIGIN, one_rr_per_rrset=True)
    forged.id = query.id
    forged.use_tsig(KEYRING, KEYNAME)
    forged.request_mac = query.mac
    # Deliberately start a brand new context instead of continuing the one
    # established by the first message.
    forged_wire = forged.to_wire(multi=True)
    assert forged.had_tsig  # the forged object claims to be signed ...
    zone = empty_zone()
    with pytest.raises(dns.tsig.BadSignature):
        feed([wires[0], forged_wire], query, zone)
    assert zone == empty_zone()


def test_consecutive_unsigned_limit_boundary():
    # Exactly the limit of consecutive unsigned middle messages is accepted.
    limit = dns.xfr.DEFAULT_MAX_UNSIGNED_MESSAGES
    texts = [AXFR_FIRST] + [AXFR_MIDDLE] * limit + [AXFR_LAST]
    signed = [True] + [False] * limit + [True]
    query = make_query(empty_zone())
    wires = build_transfer(texts, signed, query)
    zone, result = feed(wires, query, max_unsigned_messages=limit)
    assert result.message_count == limit + 2
    assert result.authenticated_count == 2


def test_consecutive_unsigned_limit_exceeded():
    limit = dns.xfr.DEFAULT_MAX_UNSIGNED_MESSAGES
    texts = [AXFR_FIRST] + [AXFR_MIDDLE] * (limit + 1) + [AXFR_LAST]
    signed = [True] + [False] * (limit + 1) + [True]
    query = make_query(empty_zone())
    wires = build_transfer(texts, signed, query)
    zone = empty_zone()
    with pytest.raises(dns.xfr.TSIGPolicyError):
        feed(wires, query, zone, max_unsigned_messages=limit)
    assert zone == empty_zone()


def test_two_transfers_can_interleave():
    # Each AuthenticatedInbound keeps its own continuous TSIG context, so
    # messages from two independent transfers may be interleaved without
    # cross-contaminating the authentication state.
    query_a = make_query(empty_zone())
    query_b = make_query(empty_zone())
    wires_a = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, False, True], query_a
    )
    wires_b = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, False, True], query_b
    )
    zone_a = empty_zone()
    zone_b = empty_zone()
    inbound_a = dns.xfr.AuthenticatedInbound(zone_a, KEYRING, query_a.mac)
    inbound_b = dns.xfr.AuthenticatedInbound(zone_b, KEYRING, query_b.mac)
    inbound_a.process_wire(wires_a[0])
    inbound_b.process_wire(wires_b[0])
    inbound_a.process_wire(wires_a[1])
    inbound_b.process_wire(wires_b[1])
    assert inbound_a.process_wire(wires_a[2]) is True
    assert inbound_b.process_wire(wires_b[2]) is True
    result_a = inbound_a.finish()
    result_b = inbound_b.finish()
    expected = dns.zone.from_text(AXFR_BASE, "example")
    assert zone_a == expected
    assert zone_b == expected
    assert result_a.authenticated_count == 2
    assert result_b.authenticated_count == 2


def test_successful_ixfr():
    zone = dns.zone.from_text(IXFR_BASE, "example", zone_factory=dns.versioned.Zone)
    query = make_query(zone, dns.rdatatype.IXFR, serial=1)
    wires = build_transfer([IXFR], [True], query)
    zone, result = feed(wires, query, zone, rdtype=dns.rdatatype.IXFR, serial=1)
    assert zone == dns.zone.from_text(IXFR_EXPECTED, "example")
    assert result.serial == 2
    assert result.message_count == 1
    assert result.authenticated_count == 1


def test_ixfr_bad_serial_is_authenticated_but_rolled_back():
    # The MAC is valid, so authentication passes, but the IXFR semantics are
    # wrong; the transaction must still roll back and the zone stay intact.
    zone = dns.zone.from_text(IXFR_BASE, "example", zone_factory=dns.versioned.Zone)
    snapshot = dns.zone.from_text(IXFR_BASE, "example")
    query = make_query(zone, dns.rdatatype.IXFR, serial=1)
    wires = build_transfer([IXFR_BAD_SERIAL], [True], query)
    with pytest.raises(dns.exception.FormError):
        feed(wires, query, zone, rdtype=dns.rdatatype.IXFR, serial=1)
    assert zone == snapshot


def test_no_writer_commit_before_authentication_completes():
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_FIRST, AXFR_LAST], [True, False], query)
    zone = empty_zone()
    commits = []
    original_commit = dns.transaction.Transaction.commit

    def counting_commit(self):
        if self.manager is zone and not self.read_only:
            commits.append(True)
        return original_commit(self)

    dns.transaction.Transaction.commit = counting_commit
    try:
        with pytest.raises(dns.xfr.TSIGPolicyError):
            feed(wires, query, zone)
    finally:
        dns.transaction.Transaction.commit = original_commit
    # A failed authenticated transfer must never publish a new zone.
    assert commits == []
    assert zone == empty_zone()


def test_request_mac_is_required():
    zone = empty_zone()
    with pytest.raises(ValueError):
        dns.xfr.AuthenticatedInbound(zone, KEYRING, b"")


def test_processing_after_failure_is_rejected():
    query = make_query(empty_zone())
    wires = build_transfer([AXFR_FIRST], [True], query)
    zone = empty_zone()
    inbound = dns.xfr.AuthenticatedInbound(zone, KEYRING, query.mac)
    inbound.process_wire(wires[0])
    with pytest.raises(dns.xfr.TransferIncomplete):
        inbound.cancel()
    with pytest.raises(dns.xfr.TSIGPolicyError):
        inbound.process_wire(wires[0])
    with pytest.raises(dns.xfr.TransferIncomplete):
        inbound.finish()


def test_works_with_unversioned_zone():
    # The entry point must not depend on the versioned Zone implementation.
    query = make_query(dns.zone.Zone("example"))
    wires = build_transfer(
        [AXFR_FIRST, AXFR_MIDDLE, AXFR_LAST], [True, False, True], query
    )
    zone = dns.zone.Zone("example")
    with dns.xfr.AuthenticatedInbound(zone, KEYRING, query.mac) as inbound:
        for wire in wires:
            inbound.process_wire(wire)
        result = inbound.finish()
    assert zone == dns.zone.from_text(AXFR_BASE, "example")
    assert result.authenticated_count == 2


IXFR_AS_AXFR_FIRST = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
"""

IXFR_AS_AXFR_LAST = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;ANSWER
ns1 3600 IN A 10.0.0.1
@ 3600 IN SOA foo bar 1 2 3 4 5
"""


def test_ixfr_request_with_axfr_style_response():
    zone = dns.zone.from_text(IXFR_BASE, "example", zone_factory=dns.versioned.Zone)
    query = make_query(zone, dns.rdatatype.IXFR, serial=0xFFFFFFFF)
    wires = build_transfer([IXFR_AS_AXFR_FIRST, IXFR_AS_AXFR_LAST], [True, True], query)
    setup_calls = []
    with dns.xfr.AuthenticatedInbound(
        zone,
        KEYRING,
        query.mac,
        rdtype=dns.rdatatype.IXFR,
        serial=0xFFFFFFFF,
        transaction_setup=lambda txn: setup_calls.append(txn),
    ) as inbound:
        assert inbound.process_wire(wires[0]) is False
        assert inbound.process_wire(wires[1]) is True
        result = inbound.finish()
    # The AXFR-style fallback rolls back and opens a replacement writer, so
    # the setup hook runs twice; authentication still gates the final commit.
    assert len(setup_calls) == 2
    assert zone == dns.zone.from_text(IXFR_BASE, "example")
    assert result.authenticated_count == 2


def test_up_to_date_ixfr_commits_with_single_signed_message():
    zone = dns.zone.from_text(IXFR_BASE, "example", zone_factory=dns.versioned.Zone)
    good_empty = """id 1
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
"""
    query = make_query(zone, dns.rdatatype.IXFR, serial=1)
    wires = build_transfer([good_empty], [True], query)
    with dns.xfr.AuthenticatedInbound(
        zone, KEYRING, query.mac, rdtype=dns.rdatatype.IXFR, serial=1
    ) as inbound:
        assert inbound.process_wire(wires[0]) is True
        result = inbound.finish()
    assert result.serial == 1
    assert result.message_count == 1
    assert result.authenticated_count == 1


def test_negative_unsigned_limit_rejected():
    with pytest.raises(ValueError):
        dns.xfr.AuthenticatedInbound(
            empty_zone(), KEYRING, b"\x01" * 8, max_unsigned_messages=-1
        )
