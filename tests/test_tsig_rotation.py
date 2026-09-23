# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for TSIG key rotation and classifiable validation results."""

import base64
from unittest.mock import patch

import pytest

import dns.message
import dns.name
import dns.rcode
import dns.tsig
import dns.tsigkeyring

KEYNAME = dns.name.from_text("rotkey")
OTHER_KEYNAME = dns.name.from_text("otherkey")

OLD_SECRET = b"0123456789abcdef" * 2
NEW_SECRET = b"fedcba9876543210" * 2

T0 = 1_700_000_000  # the rotation instant
FUDGE = 300

old_key = dns.tsig.Key(KEYNAME, OLD_SECRET, dns.tsig.HMAC_SHA256)
new_key = dns.tsig.Key(KEYNAME, NEW_SECRET, dns.tsig.HMAC_SHA256)


def make_ring():
    """A rotation keyring: the old key is valid before T0, the new key
    from T0 onwards."""
    return dns.tsigkeyring.RotationKeyring(
        dns.tsigkeyring.RotationKey(new_key, not_before=T0),
        dns.tsigkeyring.RotationKey(old_key, not_after=T0),
    )


def signed_query(key, now, mid=1, request_mac=b"", multi=False, tsig_ctx=None):
    """Make a TSIG-signed query at a fixed time, returning (message, wire)."""
    msg = dns.message.make_query("example", "a", id=mid)
    msg.use_tsig(key, fudge=FUDGE)
    msg.request_mac = request_mac
    with patch("time.time", return_value=now):
        wire = msg.to_wire(multi=multi, tsig_ctx=tsig_ctx)
    return msg, wire


def parse(wire, keyring, now, **kwargs):
    with patch("time.time", return_value=now):
        return dns.message.from_wire(wire, keyring=keyring, **kwargs)


def tsig_start_of(wire, keyring, now):
    # dns.tsig.validate() needs the exact byte offset of the TSIG record,
    # which dns.message.from_wire() computes during parsing; capture it.
    captured = {}
    real_validate = dns.tsig.validate

    def spy(*args, **kwargs):
        captured["tsig_start"] = args[6]
        return real_validate(*args, **kwargs)

    with (
        patch("dns.tsig.validate", side_effect=spy),
        patch("time.time", return_value=now),
    ):
        dns.message.from_wire(wire, keyring=keyring)
    return captured["tsig_start"]


def wire_and_start(key, now, mid=1):
    msg, wire = signed_query(key, now, mid=mid)
    start = tsig_start_of(wire, {KEYNAME: key.secret}, now)
    return msg, wire, start


def test_validate_with_result_ok():
    msg, wire, start = wire_and_start(new_key, T0 + 10)
    result = dns.tsig.validate_with_result(
        wire, new_key, KEYNAME, msg.tsig[0], T0 + 10, b"", start
    )
    assert result.ok
    assert bool(result)
    assert result.error is None
    assert result.rcode is None
    assert result.server_time is None
    assert result.ctx is None  # not a multi-message sequence
    assert result.key_name == KEYNAME


def test_error_rcodes_are_classifiable():
    assert dns.tsig.BadKey.rcode == dns.rcode.BADKEY
    assert dns.tsig.BadSignature.rcode == dns.rcode.BADSIG
    assert dns.tsig.BadTime.rcode == dns.rcode.BADTIME
    assert dns.tsig.BadAlgorithm.rcode == dns.rcode.BADALG


def test_badtime_result_carries_server_time():
    msg, wire, start = wire_and_start(new_key, T0 + 10)
    server_now = T0 + 10 + FUDGE + 1
    result = dns.tsig.validate_with_result(
        wire, new_key, KEYNAME, msg.tsig[0], server_now, b"", start
    )
    assert not result.ok
    assert not result
    assert result.error == "BADTIME"
    assert result.rcode == dns.rcode.BADTIME
    # the server time is provided so the peer can calibrate its clock
    assert result.server_time == server_now
    # ... but a BADTIME result is not a successful validation
    assert result.ctx is None


def test_badtime_result_with_multi_is_not_successful():
    # Even in a multi-message sequence, BADTIME produces no continuation
    # context, so the chain cannot continue as if validation succeeded.
    msg, wire = signed_query(new_key, T0 + 10, multi=True)
    start = tsig_start_of(wire, {KEYNAME: NEW_SECRET}, T0 + 10)
    server_now = T0 + 10 + FUDGE + 1
    result = dns.tsig.validate_with_result(
        wire, new_key, KEYNAME, msg.tsig[0], server_now, b"", start, multi=True
    )
    assert not result.ok
    assert result.error == "BADTIME"
    assert result.server_time == server_now
    assert result.ctx is None


def test_from_wire_badtime_raises_with_server_time():
    _, wire = signed_query(new_key, T0 + 10)
    server_now = T0 + 10 + FUDGE + 1
    with pytest.raises(dns.tsig.BadTime) as excinfo:
        parse(wire, make_ring(), server_now)
    assert excinfo.value.server_time == server_now
    assert excinfo.value.rcode == dns.rcode.BADTIME


def test_badtime_default_server_time_is_none():
    assert dns.tsig.BadTime().server_time is None


def test_rotation_boundary_second():
    ring = make_ring()
    # the last second of the old key
    _, wire = signed_query(old_key, T0 - 1)
    parse(wire, ring, T0 - 1)
    # the first second of the new key
    _, wire = signed_query(new_key, T0)
    parse(wire, ring, T0)


def test_new_key_not_valid_before_rotation():
    # Signed with the new key one second before it becomes valid; the
    # ring selects the old key for that signing time and the MAC made
    # with the new key does not verify.
    _, wire = signed_query(new_key, T0 - 1)
    with pytest.raises(dns.tsig.BadSignature):
        parse(wire, make_ring(), T0 - 1)


def test_no_silent_fallback_to_previous_key():
    # Signed with the old key after the rotation.  The MAC is good under
    # the old key...
    _, wire = signed_query(old_key, T0 + 1)
    parse(wire, {KEYNAME: OLD_SECRET}, T0 + 1)
    # ... but the rotation keyring selects the new key based on the
    # message's signing time and must not fall back to the old key.
    with pytest.raises(dns.tsig.BadSignature):
        parse(wire, make_ring(), T0 + 1)


def test_retry_with_new_and_old_key_in_rotation_window():
    # During the rotation window the same message may be retried with
    # either key; each copy validates against the key selected by its
    # own signing time.
    ring = make_ring()
    _, old_wire = signed_query(old_key, T0 - 1, mid=99)
    _, new_wire = signed_query(new_key, T0 + 1, mid=99)
    parse(old_wire, ring, T0 - 1)
    parse(new_wire, ring, T0 + 1)


def test_unknown_key_name():
    ring = make_ring()
    assert ring.get_key(OTHER_KEYNAME, T0) is None
    assert OTHER_KEYNAME not in ring
    other = dns.tsig.Key(OTHER_KEYNAME, NEW_SECRET, dns.tsig.HMAC_SHA256)
    _, wire = signed_query(other, T0 + 1)
    with pytest.raises(dns.message.UnknownTSIGKey):
        parse(wire, ring, T0 + 1)


def test_validate_with_result_badkey():
    msg, wire, start = wire_and_start(new_key, T0 + 10)
    # no key was selected (e.g. by a rotation keyring)
    result = dns.tsig.validate_with_result(
        wire, None, KEYNAME, msg.tsig[0], T0 + 10, b"", start
    )
    assert not result.ok
    assert result.error == "BADKEY"
    assert result.rcode == dns.rcode.BADKEY
    assert result.ctx is None
    # the key's name does not match the owner name
    misnamed = dns.tsig.Key(OTHER_KEYNAME, NEW_SECRET, dns.tsig.HMAC_SHA256)
    result = dns.tsig.validate_with_result(
        wire, misnamed, KEYNAME, msg.tsig[0], T0 + 10, b"", start
    )
    assert not result.ok
    assert result.error == "BADKEY"
    assert result.rcode == dns.rcode.BADKEY


def test_validate_with_result_bad_algorithm():
    msg, wire, start = wire_and_start(new_key, T0 + 10)
    wrong_alg = dns.tsig.Key(KEYNAME, NEW_SECRET, dns.tsig.HMAC_SHA512)
    result = dns.tsig.validate_with_result(
        wire, wrong_alg, KEYNAME, msg.tsig[0], T0 + 10, b"", start
    )
    assert not result.ok
    assert result.error == "BADALG"
    assert result.rcode == dns.rcode.BADALG


def tamper_mac(wire, msg):
    mac = msg.tsig[0].mac
    index = wire.rindex(mac)
    return wire[:index] + bytes([mac[0] ^ 0xFF]) + wire[index + 1 :]


def test_tampered_mac():
    msg, wire, start = wire_and_start(new_key, T0 + 10)
    tampered = tamper_mac(wire, msg)
    with pytest.raises(dns.tsig.BadSignature):
        parse(tampered, make_ring(), T0 + 10)
    # at the dns.tsig level, the parsed rdata carries the tampered MAC
    mac = msg.tsig[0].mac
    tampered_rdata = msg.tsig[0].replace(mac=bytes([mac[0] ^ 0xFF]) + mac[1:])
    result = dns.tsig.validate_with_result(
        wire, new_key, KEYNAME, tampered_rdata, T0 + 10, b"", start
    )
    assert not result.ok
    assert result.error == "BADSIG"
    assert result.rcode == dns.rcode.BADSIG
    assert result.ctx is None


def test_legitimate_retry():
    ring = make_ring()
    qmsg, qwire = signed_query(new_key, T0 + 10, mid=42)
    # The same query wire may be validated again (retransmission);
    # validation does not consume any state.
    for _ in range(2):
        parsed = parse(qwire, ring, T0 + 10)
        assert parsed.id == 42
    # A response to the retried query, signed with the request MAC,
    # validates on each retry too.
    request_mac = qmsg.mac
    response = dns.message.make_response(parse(qwire, ring, T0 + 10))
    response.use_tsig(new_key, fudge=FUDGE)
    response.request_mac = request_mac
    with patch("time.time", return_value=T0 + 12):
        rwire = response.to_wire()
    for _ in range(2):
        parse(rwire, ring, T0 + 12, request_mac=request_mac)


def test_multi_message_chain_across_rotation():
    ring = make_ring()
    q = dns.message.from_text("id 1\n;QUESTION\nexample. IN AXFR\n")
    q.use_tsig(old_key, fudge=FUDGE)
    with patch("time.time", return_value=T0 - 3):
        w0 = q.to_wire()
    assert w0 is not None
    m1 = dns.message.from_text(
        "id 1\nflags QR\n;QUESTION\nexample. IN AXFR\n;ANSWER\n"
        "example. 300 IN SOA . . 1 2 3 4 5\n"
        "example. 300 IN NS ns1.tld.\n"
    )
    m1.use_tsig(old_key, fudge=FUDGE)
    m1.request_mac = q.mac
    with patch("time.time", return_value=T0 - 2):
        w1 = m1.to_wire(multi=True)
    # this message is signed after the rotation, with the new key, but
    # continues the same TCP TSIG chain
    m2 = dns.message.from_text(
        "id 1\nflags QR\n;ANSWER\n"
        "example. 300 IN MX 10 mail.tld.\n"
        "example. 300 IN SOA . . 1 2 3 4 5\n"
    )
    m2.use_tsig(new_key, fudge=FUDGE)
    with patch("time.time", return_value=T0 + 2):
        w2 = m2.to_wire(multi=True, tsig_ctx=m1.tsig_ctx)

    p1 = parse(w1, ring, T0 - 2, request_mac=q.mac, multi=True)
    p2 = parse(w2, ring, T0 + 2, multi=True, tsig_ctx=p1.tsig_ctx)
    # not raising means the chain validated across the rotation boundary
    assert p1 == m1
    assert p2 == m2


def test_signing_selects_key_by_local_time():
    ring = make_ring()
    msg = dns.message.make_query("example", "a", id=1)
    with patch("time.time", return_value=T0 - 1):
        msg.use_tsig(ring)
    assert msg.keyring is old_key
    msg = dns.message.make_query("example", "a", id=2)
    with patch("time.time", return_value=T0):
        msg.use_tsig(ring)  # default keyname comes from the ring
    assert msg.keyring is new_key


def test_wire_round_trip():
    ring = make_ring()
    msg = dns.message.make_query("example", "a", id=7)
    with patch("time.time", return_value=T0 + 5):
        msg.use_tsig(ring, fudge=FUDGE)
        wire = msg.to_wire()
    parsed = parse(wire, ring, T0 + 5)
    assert parsed.had_tsig
    # the verified TSIG record is rendered identically
    assert parsed.to_wire() == wire


def test_error_objects_do_not_leak_secret():
    ring = make_ring()
    old_b64 = base64.b64encode(OLD_SECRET).decode()
    new_b64 = base64.b64encode(NEW_SECRET).decode()
    haystacks = [repr(ring), repr(ring.current), repr(ring.previous)]
    msg, wire, start = wire_and_start(new_key, T0 + 10)
    mac = msg.tsig[0].mac
    tampered_rdata = msg.tsig[0].replace(mac=bytes([mac[0] ^ 0xFF]) + mac[1:])
    results = [
        dns.tsig.validate_with_result(
            wire, None, KEYNAME, msg.tsig[0], T0 + 10, b"", start
        ),
        dns.tsig.validate_with_result(
            wire, new_key, KEYNAME, msg.tsig[0], T0 + 10 + FUDGE + 1, b"", start
        ),
        dns.tsig.validate_with_result(
            wire, new_key, KEYNAME, tampered_rdata, T0 + 10, b"", start
        ),
    ]
    haystacks.extend(repr(result) for result in results)
    try:
        dns.tsig.validate(
            wire, new_key, KEYNAME, msg.tsig[0], T0 + 10 + FUDGE + 1, b"", start
        )
    except dns.tsig.BadTime as e:
        haystacks.append(str(e))
        haystacks.append(repr(e))
    for haystack in haystacks:
        assert old_b64 not in haystack
        assert new_b64 not in haystack
        assert OLD_SECRET.decode() not in haystack
        assert NEW_SECRET.decode() not in haystack
