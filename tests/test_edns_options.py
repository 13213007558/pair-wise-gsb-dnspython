# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for EDNS unknown-option preservation and editing."""

import copy
import socket
import struct
import threading

import pytest

import dns.edns
import dns.exception
import dns.message
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.tsigkeyring

PRIVATE1 = 65001
PRIVATE2 = 65002


def make_message(options):
    q = dns.message.make_query("example.com.", dns.rdatatype.A)
    q.id = 0x1234
    q.use_edns(edns=0, payload=1232, options=options)
    return q


def standard_options():
    return [
        dns.edns.GenericOption(PRIVATE1, b"\x01\x02\x03\x04"),
        dns.edns.CookieOption(b"12345678", b"abcdefgh"),
        # Same private code appears twice; it must not be collapsed.
        dns.edns.GenericOption(PRIVATE1, b"second occurrence"),
        dns.edns.GenericOption(dns.edns.PADDING, b"\x00" * 7),
        dns.edns.GenericOption(PRIVATE2, b"zzz"),
    ]


def test_unknown_options_preserved_byte_for_byte():
    q = make_message(standard_options())
    wire = q.to_wire()
    m = dns.message.from_wire(wire)

    assert isinstance(m.options[0], dns.edns.GenericOption)
    assert m.options[0].otype == PRIVATE1
    assert m.options[0].data == b"\x01\x02\x03\x04"
    # Known options are still parsed to dedicated classes.
    assert isinstance(m.options[1], dns.edns.CookieOption)
    assert m.options[1].client == b"12345678"
    assert m.options[1].server == b"abcdefgh"
    assert m.options[2].data == b"second occurrence"
    assert m.options[3].otype == dns.edns.OptionType.PADDING
    assert m.options[3].data == b"\x00" * 7
    assert m.options[4].data == b"zzz"

    # Unmodified message re-renders identically.
    assert m.to_wire() == wire


def test_duplicate_codes_not_collapsed():
    q = make_message(standard_options())
    m = dns.message.from_wire(q.to_wire())
    matches = m.get_options(PRIVATE1)
    assert len(matches) == 2
    assert [o.data for o in matches] == [
        b"\x01\x02\x03\x04",
        b"second occurrence",
    ]


def test_delete_options():
    q = make_message(standard_options())
    m = dns.message.from_wire(q.to_wire())

    assert m.delete_options(PRIVATE1) == 2
    # Remaining options keep their order.
    assert [o.otype for o in m.options] == [
        dns.edns.OptionType.COOKIE,
        dns.edns.OptionType.PADDING,
        PRIVATE2,
    ]
    # Deleting again deletes nothing.
    assert m.delete_options(PRIVATE1) == 0

    # The new wire matches a message that never had the deleted options.
    expected = make_message(
        [
            dns.edns.CookieOption(b"12345678", b"abcdefgh"),
            dns.edns.GenericOption(dns.edns.PADDING, b"\x00" * 7),
            dns.edns.GenericOption(PRIVATE2, b"zzz"),
        ]
    )
    assert m.to_wire() == expected.to_wire()


def test_replace_options_keeps_first_position():
    q = make_message(standard_options())
    m = dns.message.from_wire(q.to_wire())

    replacement = dns.edns.GenericOption(PRIVATE1, b"replaced")
    m.replace_options(PRIVATE1, replacement)

    assert [o.otype for o in m.options] == [
        PRIVATE1,
        dns.edns.OptionType.COOKIE,
        dns.edns.OptionType.PADDING,
        PRIVATE2,
    ]
    assert m.get_options(PRIVATE1) == [replacement]

    expected = make_message(
        [
            replacement,
            dns.edns.CookieOption(b"12345678", b"abcdefgh"),
            dns.edns.GenericOption(dns.edns.PADDING, b"\x00" * 7),
            dns.edns.GenericOption(PRIVATE2, b"zzz"),
        ]
    )
    assert m.to_wire() == expected.to_wire()


def test_replace_unknown_code_appends_at_tail():
    q = make_message(standard_options())
    m = dns.message.from_wire(q.to_wire())
    new = [
        dns.edns.GenericOption(65003, b"a"),
        dns.edns.GenericOption(65003, b"b"),
    ]
    m.replace_options(65003, new)
    assert [o.otype for o in m.options[-2:]] == [65003, 65003]
    assert [o.data for o in m.get_options(65003)] == [b"a", b"b"]


def test_replace_rejects_wrong_code():
    q = make_message(standard_options())
    m = dns.message.from_wire(q.to_wire())
    with pytest.raises(ValueError):
        m.replace_options(PRIVATE1, dns.edns.GenericOption(PRIVATE2, b"x"))
    # Nothing changed.
    assert m.to_wire() == q.to_wire()


def test_append_options_tail_rule():
    q = make_message(standard_options())
    m = dns.message.from_wire(q.to_wire())

    m.append_options(dns.edns.GenericOption(PRIVATE1, b"third"))
    m.append_options(
        [
            dns.edns.CookieOption(b"87654321", b""),
            dns.edns.GenericOption(PRIVATE2, b"tail"),
        ]
    )

    assert [o.otype for o in m.options] == [
        PRIVATE1,
        dns.edns.OptionType.COOKIE,
        PRIVATE1,
        dns.edns.OptionType.PADDING,
        PRIVATE2,
        PRIVATE1,
        dns.edns.OptionType.COOKIE,
        PRIVATE2,
    ]
    assert m.get_options(PRIVATE1)[2].data == b"third"


def test_append_vs_expected_wire():
    q = make_message(standard_options())
    m = dns.message.from_wire(q.to_wire())
    added = dns.edns.GenericOption(65004, b"new")
    m.append_options(added)
    expected = make_message(standard_options() + [added])
    assert m.to_wire() == expected.to_wire()


def test_editing_without_edns():
    q = dns.message.make_query("example.com.", dns.rdatatype.A)
    assert q.options == ()
    # Deleting is a no-op on a message without EDNS.
    assert q.delete_options(PRIVATE1) == 0
    # Appending or replacing requires EDNS.
    with pytest.raises(ValueError):
        q.append_options(dns.edns.GenericOption(PRIVATE1, b"x"))
    with pytest.raises(ValueError):
        q.replace_options(PRIVATE1, dns.edns.GenericOption(PRIVATE1, b"x"))


def test_no_edns_message_unchanged():
    q = dns.message.make_query("example.com.", dns.rdatatype.A)
    wire = q.to_wire()
    m = dns.message.from_wire(wire)
    assert m.opt is None
    assert m.options == ()
    assert m.to_wire() == wire


def test_padding_option_preserved_through_roundtrip():
    q = dns.message.make_query("example.com.", dns.rdatatype.A, use_edns=0, pad=128)
    wire = q.to_wire()
    assert len(wire) == 128
    m = dns.message.from_wire(wire)
    pads = m.get_options(dns.edns.OptionType.PADDING)
    assert len(pads) == 1
    assert set(pads[0].data) == {0}
    # The padding option is retained verbatim on re-render.
    assert m.to_wire() == wire


def test_duplicate_padding_options_preserved():
    q = make_message(
        [
            dns.edns.GenericOption(dns.edns.PADDING, b"\x00"),
            dns.edns.GenericOption(dns.edns.PADDING, b"\x00\x00"),
        ]
    )
    m = dns.message.from_wire(q.to_wire())
    assert len(m.get_options(dns.edns.PADDING)) == 2
    assert m.to_wire() == q.to_wire()


def test_cookie_known_class_roundtrip():
    options = [
        dns.edns.CookieOption(b"12345678", b""),
        dns.edns.GenericOption(PRIVATE1, b"x"),
    ]
    q = make_message(options)
    m = dns.message.from_wire(q.to_wire())
    assert isinstance(m.options[0], dns.edns.CookieOption)
    assert m.to_wire() == q.to_wire()


def test_payload_too_long_rejected():
    with pytest.raises(ValueError):
        dns.edns.GenericOption(PRIVATE1, b"\x00" * 65536)


def test_bad_option_length_raises_formerror():
    q = make_message([dns.edns.GenericOption(PRIVATE1, b"abcd")])
    wire = bytearray(q.to_wire())
    # OPT RR rdata starts with the option; bump its length past rdata end.
    marker = struct.pack("!HH", PRIVATE1, 4)
    pos = wire.find(marker)
    assert pos > 0
    wire[pos + 2 : pos + 4] = struct.pack("!H", 0xFFFF)
    with pytest.raises(dns.exception.FormError):
        dns.message.from_wire(bytes(wire))


def test_bad_cookie_length_raises():
    # A COOKIE option whose server part is 1 byte is invalid.
    cookie_data = b"12345678" + b"a"
    q = make_message([dns.edns.GenericOption(dns.edns.OptionType.COOKIE, cookie_data)])
    wire = q.to_wire()
    # Malformed option content makes the whole message parse fail with
    # FormError; no partially-built message is returned.
    with pytest.raises(dns.exception.FormError):
        dns.message.from_wire(wire)


def test_copy_and_deepcopy_preserve_options():
    q = make_message(standard_options())
    m = dns.message.from_wire(q.to_wire())
    for clone in (copy.copy(m), copy.deepcopy(m)):
        assert clone.to_wire() == q.to_wire()
        assert [o.otype for o in clone.options] == [o.otype for o in m.options]


def test_tsig_signed_message_preserves_options():
    keyring = dns.tsigkeyring.from_text({"keyname.": "NjHwPsMKjdN++dOfE5iAiQ=="})
    q = make_message(standard_options())
    q.use_tsig(keyring)
    wire = q.to_wire()
    m = dns.message.from_wire(wire, keyring=keyring)
    assert m.tsig is not None
    assert [o.otype for o in m.options] == [o.otype for o in q.options]
    assert m.get_options(PRIVATE1)[1].data == b"second occurrence"


def test_tcp_fragmentation_preserves_options():
    request = make_message(standard_options())
    server, client = socket.socketpair()
    server.settimeout(5)
    client.setblocking(False)
    seen_options = []
    error = []

    def serve():
        try:
            chunks = []
            wanted = None
            while wanted is None or sum(map(len, chunks)) < wanted:
                data = server.recv(4096)
                if not data:
                    return
                if wanted is None:
                    wanted = struct.unpack("!H", data[:2])[0]
                    data = data[2:]
                chunks.append(data)
            received = b"".join(chunks)[:wanted]
            parsed = dns.message.from_wire(received)
            seen_options.extend(parsed.options)
            response = dns.message.make_response(parsed)
            response.use_edns(
                options=[
                    dns.edns.GenericOption(PRIVATE1, b"reply"),
                    dns.edns.GenericOption(PRIVATE1, b"reply2"),
                ]
            )
            raw = response.to_wire()
            framed = struct.pack("!H", len(raw)) + raw
            # Send the response one byte at a time to exercise TCP
            # reassembly (fragmentation).
            for i in range(0, len(framed), 1):
                server.send(framed[i : i + 1])
        except Exception as e:  # pragma: no cover
            error.append(e)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        response = dns.query.tcp(request, None, sock=client, timeout=5)
    finally:
        thread.join(timeout=5)
        client.close()
        server.close()
    assert error == []
    assert [o.otype for o in seen_options] == [
        PRIVATE1,
        dns.edns.OptionType.COOKIE,
        PRIVATE1,
        dns.edns.OptionType.PADDING,
        PRIVATE2,
    ]
    assert [o.data for o in response.get_options(PRIVATE1)] == [
        b"reply",
        b"reply2",
    ]


def test_resolver_edns_config_propagates_options():
    resolver = dns.resolver.Resolver(configure=False)
    options = [
        dns.edns.GenericOption(PRIVATE1, b"resolver"),
        dns.edns.GenericOption(PRIVATE1, b"resolver2"),
    ]
    resolver.use_edns(0, 0, 1232, options=options)
    resolution = dns.resolver._Resolution(
        resolver, "example.com.", dns.rdatatype.A, dns.rdataclass.IN, False, True, None
    )
    built, _ = resolution.next_request()
    assert [o.data for o in built.get_options(PRIVATE1)] == [
        b"resolver",
        b"resolver2",
    ]
