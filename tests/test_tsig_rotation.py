# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for TSIG key rotation, clock-skew classification, and
multi-message signing.

All tests use a fixed clock.  The previous (old) key uses HMAC-SHA1 and
is valid up to but not including ROTATION_TIME; the current (new) key
uses HMAC-SHA256 and is valid from ROTATION_TIME on.
"""

import base64
from unittest.mock import patch

import dns.exception
import dns.message
import dns.name
import dns.rcode
import dns.tsig
import pytest

ROTATION_TIME = 1_700_000_000
FUDGE = 300

KEYNAME = dns.name.from_text("rotating-key")
OTHERNAME = dns.name.from_text("some-other-key")

OLD_SECRET = b"old-shared-secret-0123456789ab"
NEW_SECRET = b"new-shared-secret-0123456789ab"

OLD_KEY = dns.tsig.Key(
    KEYNAME,
    OLD_SECRET,
    dns.tsig.HMAC_SHA1,
    not_before=None,
    not_after=ROTATION_TIME,
)
NEW_KEY = dns.tsig.Key(
    KEYNAME,
    NEW_SECRET,
    dns.tsig.HMAC_SHA256,
    not_before=ROTATION_TIME,
    not_after=None,
)

KEYRING = dns.tsig.RotatingKeyring(NEW_KEY, OLD_KEY)

# A ring where both keys share an algorithm, so that picking the wrong
# key is a MAC failure (BadSignature) rather than BadAlgorithm.
SAME_ALG_OLD_KEY = dns.tsig.Key(
    KEYNAME,
    OLD_SECRET,
    dns.tsig.HMAC_SHA256,
    not_before=None,
    not_after=ROTATION_TIME,
)
SAME_ALG_RING = dns.tsig.RotatingKeyring(NEW_KEY, SAME_ALG_OLD_KEY)


def signed_wire(key, when, *, tsig_error=0):
    """Make a query and sign it with the fixed clock."""
    q = dns.message.make_query("example", "a")
    q.use_tsig(key, KEYNAME, fudge=FUDGE, tsig_error=tsig_error)
    with patch("time.time", return_value=when):
        wire = q.to_wire()
    return q, wire


def parse(wire, now, ring=KEYRING, **kwargs):
    """Parse with the rotating keyring at the fixed local time."""
    with patch("time.time", return_value=now):
        return dns.message.from_wire(wire, keyring=ring, **kwargs)


def flip_mac(wire):
    """Corrupt one byte of the trailing TSIG MAC."""
    corrupted = bytearray(wire)
    corrupted[-7] = (corrupted[-7] + 1) & 0xFF
    return bytes(corrupted)


def test_key_valid_at_interval():
    assert OLD_KEY.valid_at(ROTATION_TIME - 1)
    assert not OLD_KEY.valid_at(ROTATION_TIME)
    assert NEW_KEY.valid_at(ROTATION_TIME)
    assert not NEW_KEY.valid_at(ROTATION_TIME - 1)
    # The current key wins when both intervals overlap.
    old_overlap = dns.tsig.Key(
        KEYNAME, OLD_SECRET, not_before=None, not_after=ROTATION_TIME + 10
    )
    ring = dns.tsig.RotatingKeyring(NEW_KEY, old_overlap)
    assert ring.get_key(KEYNAME, ROTATION_TIME) is NEW_KEY
    assert ring.get_key(KEYNAME, ROTATION_TIME - 1) is old_overlap
    assert ring.get_key(OTHERNAME, ROTATION_TIME) is None


def test_rotation_boundary_second():
    # The second just before the boundary validates with the old key.
    _, old_wire = signed_wire(OLD_KEY, ROTATION_TIME - 1)
    msg = parse(old_wire, ROTATION_TIME - 1)
    assert msg.had_tsig
    assert msg.tsig[0].algorithm == dns.tsig.HMAC_SHA1

    # The boundary second itself uses the new key.
    _, new_wire = signed_wire(NEW_KEY, ROTATION_TIME)
    msg = parse(new_wire, ROTATION_TIME)
    assert msg.had_tsig
    assert msg.tsig[0].algorithm == dns.tsig.HMAC_SHA256


def test_selects_exactly_one_key_no_fallback():
    # A message signed with the old key at/after rotation must NOT be
    # silently accepted after the new key fails.  With a shared
    # algorithm this is a MAC-level BadSignature ...
    _, wire = signed_wire(SAME_ALG_OLD_KEY, ROTATION_TIME)
    with pytest.raises(dns.tsig.BadSignature):
        parse(wire, ROTATION_TIME, ring=SAME_ALG_RING)

    # Likewise, a new-key signature before the boundary is verified
    # against the old key and fails; there is no fallback either way.
    _, wire = signed_wire(NEW_KEY, ROTATION_TIME - 1)
    with pytest.raises(dns.tsig.BadSignature):
        parse(wire, ROTATION_TIME - 1, ring=SAME_ALG_RING)

    # ... and with per-key algorithms, a cross-key message is a
    # classified BadAlgorithm, still never a silent success.
    _, wire = signed_wire(OLD_KEY, ROTATION_TIME)
    with pytest.raises(dns.tsig.BadAlgorithm):
        parse(wire, ROTATION_TIME)


def test_clock_skew_badtime_is_classified_but_not_success():
    message_time = ROTATION_TIME + 1000
    _, wire = signed_wire(NEW_KEY, message_time)

    # Inside the fudge window the message verifies normally.
    msg = parse(wire, message_time + FUDGE)
    assert msg.had_tsig

    # One second beyond fudge is BadTime, carrying both clocks ...
    local_time = message_time + FUDGE + 1
    with pytest.raises(dns.tsig.BadTime) as exc_info:
        parse(wire, local_time)
    exc = exc_info.value
    assert exc.time_signed == message_time
    assert exc.now == local_time
    assert exc.now - exc.time_signed > FUDGE

    # ... and it is a verification failure, not a successful result:
    # the caller gets an exception and no validated TSIG context.
    assert isinstance(exc, dns.exception.DNSException)


def test_peer_badtime_carries_server_time():
    client_time = ROTATION_TIME + 100
    server_time = client_time + 4000

    q, qwire = signed_wire(NEW_KEY, client_time)
    parse(qwire, client_time)  # the query verifies at the client's clock

    # The server answers BADTIME, signing its own clock into the TSIG.
    r = dns.message.make_response(q, tsig_error=dns.rcode.BADTIME)
    with patch("time.time", return_value=server_time):
        rwire = r.to_wire()

    with pytest.raises(dns.tsig.PeerBadTime) as exc_info:
        parse(rwire, client_time, request_mac=q.mac)
    exc = exc_info.value
    assert exc.server_time == server_time
    # The client can use the server time to calibrate its clock.
    assert abs(exc.server_time - client_time) > FUDGE


def test_wrong_key():
    # Unknown key name: the rotating keyring has no matching key.
    other = dns.tsig.Key(OTHERNAME, b"another-secret-1234567890ab")
    _, wire = signed_wire(other, ROTATION_TIME)
    with pytest.raises(dns.message.UnknownTSIGKey):
        parse(wire, ROTATION_TIME)

    # A key name/owner mismatch in validate() is classified as BadKey.
    _, wire = signed_wire(NEW_KEY, ROTATION_TIME)
    misnamed = {KEYNAME: dns.tsig.Key("wrong-name", NEW_SECRET)}
    with patch("time.time", return_value=ROTATION_TIME):
        with pytest.raises(dns.tsig.BadKey):
            dns.message.from_wire(wire, keyring=misnamed)


def test_tampered_mac():
    _, wire = signed_wire(NEW_KEY, ROTATION_TIME)
    with pytest.raises(dns.tsig.BadSignature):
        parse(flip_mac(wire), ROTATION_TIME)


def test_legitimate_retry_with_rotated_key():
    # First attempt, still using the old key after rotation: rejected.
    q1, wire1 = signed_wire(SAME_ALG_OLD_KEY, ROTATION_TIME + 5)
    with pytest.raises(dns.tsig.BadSignature):
        parse(wire1, ROTATION_TIME + 5, ring=SAME_ALG_RING)

    # The client retries the same query content, this time signed with
    # the new key; validation succeeds.  Each attempt used one key only.
    q2, wire2 = signed_wire(NEW_KEY, ROTATION_TIME + 6)
    msg = parse(wire2, ROTATION_TIME + 6, ring=SAME_ALG_RING)
    assert msg.question == q1.question == q2.question
    assert msg.had_tsig
    assert msg.tsig[0].algorithm == dns.tsig.HMAC_SHA256


def test_signing_via_rotating_keyring_picks_valid_key():
    # use_tsig() treats the keyring as a callable and selects the key
    # valid at signing time (fixed clock).
    with patch("time.time", return_value=ROTATION_TIME + 1):
        q = dns.message.make_query("example", "a")
        q.use_tsig(KEYRING, KEYNAME, fudge=FUDGE)
        wire = q.to_wire()
    msg = parse(wire, ROTATION_TIME + 1)
    assert msg.tsig[0].algorithm == dns.tsig.HMAC_SHA256

    with patch("time.time", return_value=ROTATION_TIME - 1):
        q = dns.message.make_query("example", "a")
        q.use_tsig(KEYRING, KEYNAME, fudge=FUDGE)
        wire = q.to_wire()
    msg = parse(wire, ROTATION_TIME - 1)
    assert msg.tsig[0].algorithm == dns.tsig.HMAC_SHA1


def _axfr_messages():
    tm0 = """id 1
;QUESTION
example. IN AXFR
"""
    tm1 = """id 1
flags QR
;QUESTION
example. IN AXFR
;ANSWER
example. 300 IN SOA . . 1 2 3 4 5
example. 300 IN NS ns1.tld.
example. 300 IN NS ns2.tld.
"""
    tm2 = """id 1
flags QR
;ANSWER
example. 300 IN MX 10 mail.tld.
example. 300 IN SOA . . 1 2 3 4 5
"""
    return (
        dns.message.from_text(tm0),
        dns.message.from_text(tm1),
        dns.message.from_text(tm2),
    )


def test_tcp_multi_message_prior_mac_chaining():
    m0, m1, m2 = _axfr_messages()
    base = ROTATION_TIME + 10

    m0.use_tsig(NEW_KEY, KEYNAME, fudge=FUDGE)
    with patch("time.time", return_value=base):
        m0.to_wire()
    m1.use_tsig(NEW_KEY, KEYNAME, fudge=FUDGE)
    m1.request_mac = m0.mac
    with patch("time.time", return_value=base + 1):
        w1 = m1.to_wire(multi=True)
    m2.use_tsig(NEW_KEY, KEYNAME, fudge=FUDGE)
    with patch("time.time", return_value=base + 2):
        w2 = m2.to_wire(multi=True, tsig_ctx=m1.tsig_ctx)

    with patch("time.time", return_value=base + 1):
        m3 = dns.message.from_wire(w1, keyring=KEYRING, request_mac=m0.mac, multi=True)
    with patch("time.time", return_value=base + 2):
        m4 = dns.message.from_wire(
            w2, keyring=KEYRING, multi=True, tsig_ctx=m3.tsig_ctx
        )
    assert m1 == m3
    assert m2 == m4


def test_tcp_multi_message_tampered_mac_fails():
    m0, m1, _ = _axfr_messages()
    base = ROTATION_TIME + 20
    m0.use_tsig(NEW_KEY, KEYNAME, fudge=FUDGE)
    with patch("time.time", return_value=base):
        m0.to_wire()
    m1.use_tsig(NEW_KEY, KEYNAME, fudge=FUDGE)
    m1.request_mac = m0.mac
    with patch("time.time", return_value=base + 1):
        w1 = m1.to_wire(multi=True)

    with patch("time.time", return_value=base + 1):
        with pytest.raises(dns.tsig.BadSignature):
            dns.message.from_wire(
                flip_mac(w1), keyring=KEYRING, request_mac=m0.mac, multi=True
            )


def test_chain_crossing_rotation_boundary():
    # A chained sequence is authenticated by the key that started it;
    # later messages continue the MAC chain.  With a shared algorithm,
    # a chain started before rotation keeps verifying after it.
    m0, m1, m2 = _axfr_messages()
    m0.use_tsig(SAME_ALG_OLD_KEY, KEYNAME, fudge=FUDGE)
    with patch("time.time", return_value=ROTATION_TIME - 3):
        m0.to_wire()
    m1.use_tsig(SAME_ALG_OLD_KEY, KEYNAME, fudge=FUDGE)
    m1.request_mac = m0.mac
    with patch("time.time", return_value=ROTATION_TIME - 2):
        w1 = m1.to_wire(multi=True)
    with patch("time.time", return_value=ROTATION_TIME - 2):
        p1 = dns.message.from_wire(
            w1, keyring=SAME_ALG_RING, request_mac=m0.mac, multi=True
        )

    m2.use_tsig(SAME_ALG_OLD_KEY, KEYNAME, fudge=FUDGE)
    with patch("time.time", return_value=ROTATION_TIME + 1):
        w2 = m2.to_wire(multi=True, tsig_ctx=m1.tsig_ctx)
    with patch("time.time", return_value=ROTATION_TIME + 1):
        p2 = dns.message.from_wire(
            w2, keyring=SAME_ALG_RING, multi=True, tsig_ctx=p1.tsig_ctx
        )
    assert p2.had_tsig

    # If the rotation also changed algorithms, the post-boundary
    # message's algorithm no longer matches the selected key and the
    # failure is classified (BadAlgorithm), never silently accepted.
    m0, m1, m2 = _axfr_messages()
    m0.use_tsig(OLD_KEY, KEYNAME, fudge=FUDGE)
    with patch("time.time", return_value=ROTATION_TIME - 3):
        m0.to_wire()
    m1.use_tsig(OLD_KEY, KEYNAME, fudge=FUDGE)
    m1.request_mac = m0.mac
    with patch("time.time", return_value=ROTATION_TIME - 2):
        w1 = m1.to_wire(multi=True)
    with patch("time.time", return_value=ROTATION_TIME - 2):
        p1 = dns.message.from_wire(w1, keyring=KEYRING, request_mac=m0.mac, multi=True)
    m2.use_tsig(OLD_KEY, KEYNAME, fudge=FUDGE)
    with patch("time.time", return_value=ROTATION_TIME + 1):
        w2 = m2.to_wire(multi=True, tsig_ctx=m1.tsig_ctx)
    with patch("time.time", return_value=ROTATION_TIME + 1):
        with pytest.raises(dns.tsig.BadAlgorithm):
            dns.message.from_wire(w2, keyring=KEYRING, multi=True, tsig_ctx=p1.tsig_ctx)


def test_errors_and_keyring_do_not_leak_secret():
    raised = []

    _, wire = signed_wire(NEW_KEY, ROTATION_TIME)
    with pytest.raises(dns.tsig.BadTime) as info:
        parse(wire, ROTATION_TIME + FUDGE + 10)
    raised.append(info.value)

    with pytest.raises(dns.tsig.BadSignature) as info:
        parse(flip_mac(wire), ROTATION_TIME)
    raised.append(info.value)

    other = dns.tsig.Key(OTHERNAME, b"another-secret-1234567890ab")
    _, other_wire = signed_wire(other, ROTATION_TIME)
    with pytest.raises(dns.message.UnknownTSIGKey) as info:
        parse(other_wire, ROTATION_TIME)
    raised.append(info.value)

    q, _ = signed_wire(NEW_KEY, ROTATION_TIME)
    r = dns.message.make_response(q, tsig_error=dns.rcode.BADTIME)
    with patch("time.time", return_value=ROTATION_TIME + 4000):
        rwire = r.to_wire()
    with pytest.raises(dns.tsig.PeerBadTime) as info:
        parse(rwire, ROTATION_TIME, request_mac=q.mac)
    raised.append(info.value)

    secrets = [
        OLD_SECRET.decode(),
        NEW_SECRET.decode(),
        base64.b64encode(OLD_SECRET).decode(),
        base64.b64encode(NEW_SECRET).decode(),
    ]
    for exc in raised:
        text = str(exc) + repr(exc) + repr(vars(exc))
        for secret in secrets:
            assert secret not in text
    for secret in secrets:
        assert secret not in repr(KEYRING)


def test_wire_roundtrip():
    _, wire = signed_wire(NEW_KEY, ROTATION_TIME)
    msg = parse(wire, ROTATION_TIME)
    assert msg.to_wire() == wire

    _, wire = signed_wire(OLD_KEY, ROTATION_TIME - 1)
    msg = parse(wire, ROTATION_TIME - 1)
    assert msg.to_wire() == wire
