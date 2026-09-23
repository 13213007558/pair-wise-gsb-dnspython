# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import sys

import pytest

import dns.asyncbackend
import dns.asyncquery
import dns.message
import dns.query
import dns.tsigkeyring
import dns.versioned
import dns.xfr

# Some tests use a "nano nameserver" for testing.  It requires trio
# and threading, so try to import it and if it doesn't work, skip
# those tests.
try:
    from .nanonameserver import Server

    _nanonameserver_available = True
except ImportError:
    _nanonameserver_available = False

    class Server(object):
        pass


axfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN AXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
@ 3600 IN SOA foo bar 1 2 3 4 5
"""

axfr1 = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN AXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
"""
axfr2 = """id 1
opcode QUERY
rcode NOERROR
flags AA
;ANSWER
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
@ 3600 IN SOA foo bar 1 2 3 4 5
"""

base = """@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
"""

axfr_unexpected_origin = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN AXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN SOA foo bar 1 2 3 4 7
"""

axfr_with_nonsubdomain_glue = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN AXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
sub 300 IN NS ns1.other.
ns1.other. 300 IN A 1.2.3.4
@ 3600 IN SOA foo bar 1 2 3 4 5
"""

ixfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN SOA foo bar 1 2 3 4 5
bar.foo 300 IN MX 0 blaz.foo
ns2 3600 IN A 10.0.0.2
@ 3600 IN SOA foo bar 2 2 3 4 5
ns2 3600 IN A 10.0.0.4
@ 3600 IN SOA foo bar 2 2 3 4 5
@ 3600 IN SOA foo bar 3 2 3 4 5
ns3 3600 IN A 10.0.0.3
@ 3600 IN SOA foo bar 3 2 3 4 5
@ 3600 IN NS ns2
@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN SOA foo bar 4 2 3 4 5
"""

compressed_ixfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN SOA foo bar 1 2 3 4 5
bar.foo 300 IN MX 0 blaz.foo
ns2 3600 IN A 10.0.0.2
@ 3600 IN NS ns2
@ 3600 IN SOA foo bar 4 2 3 4 5
ns2 3600 IN A 10.0.0.4
ns3 3600 IN A 10.0.0.3
@ 3600 IN SOA foo bar 4 2 3 4 5
"""

ixfr_expected = """@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN NS ns1
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.4
ns3 3600 IN A 10.0.0.3
"""

ixfr_first_message = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 4 2 3 4 5
"""

ixfr_header = """id 1
opcode QUERY
rcode NOERROR
flags AA
;ANSWER
"""

ixfr_body = [
    "@ 3600 IN SOA foo bar 1 2 3 4 5",
    "bar.foo 300 IN MX 0 blaz.foo",
    "ns2 3600 IN A 10.0.0.2",
    "@ 3600 IN SOA foo bar 2 2 3 4 5",
    "ns2 3600 IN A 10.0.0.4",
    "@ 3600 IN SOA foo bar 2 2 3 4 5",
    "@ 3600 IN SOA foo bar 3 2 3 4 5",
    "ns3 3600 IN A 10.0.0.3",
    "@ 3600 IN SOA foo bar 3 2 3 4 5",
    "@ 3600 IN NS ns2",
    "@ 3600 IN SOA foo bar 4 2 3 4 5",
    "@ 3600 IN SOA foo bar 4 2 3 4 5",
]

ixfrs = [ixfr_first_message]
ixfrs.extend([ixfr_header + l for l in ixfr_body])

good_empty_ixfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
"""

retry_tcp_ixfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 5 2 3 4 5
"""

bad_empty_ixfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN SOA foo bar 4 2 3 4 5
"""

unexpected_end_ixfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN SOA foo bar 1 2 3 4 5
bar.foo 300 IN MX 0 blaz.foo
ns2 3600 IN A 10.0.0.2
@ 3600 IN NS ns2
@ 3600 IN SOA foo bar 3 2 3 4 5
ns2 3600 IN A 10.0.0.4
ns3 3600 IN A 10.0.0.3
@ 3600 IN SOA foo bar 4 2 3 4 5
"""

unexpected_end_ixfr_2 = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN SOA foo bar 1 2 3 4 5
bar.foo 300 IN MX 0 blaz.foo
ns2 3600 IN A 10.0.0.2
@ 3600 IN NS ns2
"""

bad_serial_ixfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 4 2 3 4 5
@ 3600 IN SOA foo bar 2 2 3 4 5
bar.foo 300 IN MX 0 blaz.foo
ns2 3600 IN A 10.0.0.2
@ 3600 IN NS ns2
@ 3600 IN SOA foo bar 4 2 3 4 5
ns2 3600 IN A 10.0.0.4
ns3 3600 IN A 10.0.0.3
@ 3600 IN SOA foo bar 4 2 3 4 5
"""

ixfr_axfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
@ 3600 IN SOA foo bar 1 2 3 4 5
"""

ixfr_axfr1 = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
"""

ixfr_axfr2 = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
@ 3600 IN SOA foo bar 1 2 3 4 5
"""


def test_basic_axfr():
    z = dns.versioned.Zone("example.")
    m = dns.message.from_text(axfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.AXFR) as xfr:
        done = xfr.process_message(m)
        assert done
    ez = dns.zone.from_text(base, "example.")
    assert z == ez


def test_basic_axfr_unversioned():
    z = dns.zone.Zone("example.")
    m = dns.message.from_text(axfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.AXFR) as xfr:
        done = xfr.process_message(m)
        assert done
    ez = dns.zone.from_text(base, "example.")
    assert z == ez


def test_basic_axfr_two_parts():
    z = dns.versioned.Zone("example.")
    m1 = dns.message.from_text(axfr1, origin=z.origin, one_rr_per_rrset=True)
    m2 = dns.message.from_text(axfr2, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.AXFR) as xfr:
        done = xfr.process_message(m1)
        assert not done
        done = xfr.process_message(m2)
        assert done
    ez = dns.zone.from_text(base, "example.")
    assert z == ez


def test_axfr_unexpected_origin():
    z = dns.versioned.Zone("example.")
    m = dns.message.from_text(
        axfr_unexpected_origin, origin=z.origin, one_rr_per_rrset=True
    )
    with dns.xfr.Inbound(z, dns.rdatatype.AXFR) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_axfr_with_non_subdomain_glue():
    z = dns.versioned.Zone("example.")
    m = dns.message.from_text(
        axfr_with_nonsubdomain_glue, origin=z.origin, one_rr_per_rrset=True
    )
    with dns.xfr.Inbound(z, dns.rdatatype.AXFR) as xfr:
        xfr.process_message(m)


def test_basic_ixfr():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(ixfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        done = xfr.process_message(m)
        assert done
    ez = dns.zone.from_text(ixfr_expected, "example.")
    assert z == ez


def test_basic_ixfr_unversioned():
    z = dns.zone.from_text(base, "example.")
    m = dns.message.from_text(ixfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        done = xfr.process_message(m)
        assert done
    ez = dns.zone.from_text(ixfr_expected, "example.")
    assert z == ez


def test_compressed_ixfr():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(compressed_ixfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        done = xfr.process_message(m)
        assert done
    ez = dns.zone.from_text(ixfr_expected, "example.")
    assert z == ez


def test_basic_ixfr_many_parts():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        done = False
        for text in ixfrs:
            assert not done
            m = dns.message.from_text(text, origin=z.origin, one_rr_per_rrset=True)
            done = xfr.process_message(m)
        assert done
    ez = dns.zone.from_text(ixfr_expected, "example.")
    assert z == ez


def test_good_empty_ixfr():
    z = dns.zone.from_text(ixfr_expected, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(good_empty_ixfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        done = xfr.process_message(m)
        assert done
    ez = dns.zone.from_text(ixfr_expected, "example.")
    assert z == ez


def test_retry_tcp_ixfr():
    z = dns.zone.from_text(ixfr_expected, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(retry_tcp_ixfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1, is_udp=True) as xfr:
        with pytest.raises(dns.xfr.UseTCP):
            xfr.process_message(m)


def test_bad_empty_ixfr():
    z = dns.zone.from_text(ixfr_expected, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(bad_empty_ixfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=3) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_serial_went_backwards_ixfr():
    z = dns.zone.from_text(ixfr_expected, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(bad_empty_ixfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=5) as xfr:
        with pytest.raises(dns.xfr.SerialWentBackwards):
            xfr.process_message(m)


def test_ixfr_is_axfr():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(ixfr_axfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=0xFFFFFFFF) as xfr:
        done = xfr.process_message(m)
        assert done
    ez = dns.zone.from_text(base, "example.")
    assert z == ez


def test_ixfr_is_axfr_two_parts():
    z = dns.versioned.Zone("example.")
    m1 = dns.message.from_text(ixfr_axfr1, origin=z.origin, one_rr_per_rrset=True)
    m2 = dns.message.from_text(ixfr_axfr2, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=0xFFFFFFFF) as xfr:
        done = xfr.process_message(m1)
        assert not done
        done = xfr.process_message(m2)
        assert done
    ez = dns.zone.from_text(base, "example.")
    assert z == ez


def test_ixfr_requires_serial():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    with pytest.raises(ValueError):
        dns.xfr.Inbound(z, dns.rdatatype.IXFR)


def test_ixfr_unexpected_end_bad_diff_sequence():
    # This is where we get the end serial, but haven't seen all of
    # the expected diffs
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(
        unexpected_end_ixfr, origin=z.origin, one_rr_per_rrset=True
    )
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_udp_ixfr_unexpected_end_just_stops():
    # This is where everything looks good, but the IXFR just stops
    # in the middle.
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(
        unexpected_end_ixfr_2, origin=z.origin, one_rr_per_rrset=True
    )
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1, is_udp=True) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_ixfr_bad_serial():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(bad_serial_ixfr, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_no_udp_with_axfr():
    z = dns.versioned.Zone("example.")
    with pytest.raises(ValueError):
        with dns.xfr.Inbound(z, dns.rdatatype.AXFR, is_udp=True) as xfr:
            pass


refused = """id 1
opcode QUERY
rcode REFUSED
flags AA
;QUESTION
example. IN AXFR
"""

bad_qname = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
not-example. IN IXFR
"""

bad_qtype = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN AXFR
"""

soa_not_first = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
bar.foo 300 IN MX 0 blaz.foo
"""

soa_not_first_2 = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 300 IN MX 0 blaz.foo
"""

no_answer = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ADDITIONAL
bar.foo 300 IN MX 0 blaz.foo
"""

axfr_answers_after_final_soa = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN AXFR
;ANSWER
@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
bar.foo 300 IN MX 0 blaz.foo
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.2
@ 3600 IN SOA foo bar 1 2 3 4 5
ns3 3600 IN A 10.0.0.3
"""


def test_refused():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(refused, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        with pytest.raises(dns.xfr.TransferError):
            xfr.process_message(m)


def test_bad_qname():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(bad_qname, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_bad_qtype():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(bad_qtype, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_soa_not_first():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(soa_not_first, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)
    m = dns.message.from_text(soa_not_first_2, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_no_answer():
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    m = dns.message.from_text(no_answer, origin=z.origin, one_rr_per_rrset=True)
    with dns.xfr.Inbound(z, dns.rdatatype.IXFR, serial=1) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


def test_axfr_answers_after_final_soa():
    z = dns.versioned.Zone("example.")
    m = dns.message.from_text(
        axfr_answers_after_final_soa, origin=z.origin, one_rr_per_rrset=True
    )
    with dns.xfr.Inbound(z, dns.rdatatype.AXFR) as xfr:
        with pytest.raises(dns.exception.FormError):
            xfr.process_message(m)


keyring = dns.tsigkeyring.from_text({"keyname.": "NjHwPsMKjdN++dOfE5iAiQ=="})

keyname = dns.name.from_text("keyname")


def _outbound_zone():
    """Make a versioned zone with committed versions at serials 1-4.

    The versions and the final contents match the data of the classic
    ixfr test above.
    """
    z = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    z.set_max_versions(None)
    with z.writer() as txn:
        txn.delete_exact(dns.rrset.from_text("bar.foo", 300, "in", "mx", "0 blaz.foo"))
        txn.delete_exact(dns.rrset.from_text("ns2", 3600, "in", "a", "10.0.0.2"))
        txn.add(dns.rrset.from_text("ns2", 3600, "in", "a", "10.0.0.4"))
        txn.update_serial(2, relative=False)
    with z.writer() as txn:
        txn.add(dns.rrset.from_text("ns3", 3600, "in", "a", "10.0.0.3"))
        txn.update_serial(3, relative=False)
    with z.writer() as txn:
        txn.delete_exact(dns.rrset.from_text("example.", 3600, "in", "ns", "ns2"))
        txn.update_serial(4, relative=False)
    return z


def _apply_outbound(
    query, messages, zone, serial=None, rdtype=dns.rdatatype.IXFR, keyring=None
):
    """Encode and decode each message, applying them to *zone* with Inbound."""
    with dns.xfr.Inbound(zone, rdtype, serial) as inbound:
        done = False
        send_ctx = None
        recv_ctx = None
        for message in messages:
            wire = message.to_wire(multi=True, tsig_ctx=send_ctx)
            send_ctx = message.tsig_ctx
            received = dns.message.from_wire(
                wire,
                keyring=keyring,
                request_mac=query.mac,
                xfr=True,
                origin=zone.origin,
                tsig_ctx=recv_ctx,
                multi=True,
                one_rr_per_rrset=True,
            )
            recv_ctx = received.tsig_ctx
            done = inbound.process_message(received)
        assert done


def _dump_zone(zone):
    """Dump a zone's contents, including TTLs, in a canonical form."""
    return sorted(
        (
            str(name),
            int(rds.rdtype),
            rds.ttl,
            tuple(sorted(str(rdata) for rdata in rds)),
        )
        for name, rds in zone.iterate_rdatasets()
    )


ttl_base = """@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
ns1 3600 IN A 10.0.0.1
"""


def test_outbound_basic_ixfr():
    z = _outbound_zone()
    before = z.to_text()
    query, _ = dns.xfr.make_query(z, serial=1)
    with (
        z.reader() as current,
        z.reader(serial=1) as v1,
        z.reader(serial=2) as v2,
        z.reader(serial=3) as v3,
    ):
        messages = list(dns.xfr.Outbound(query, current, [v1, v2, v3]))
    old = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    _apply_outbound(query, messages, old, serial=1)
    expected = dns.zone.from_text(ixfr_expected, "example.")
    assert old == expected
    assert old == z
    # Generating the transfer did not alter the zone or its history.
    assert z.to_text() == before


def test_outbound_ixfr_multiple_messages():
    z = dns.zone.from_text(ttl_base, "example.", zone_factory=dns.versioned.Zone)
    z.set_max_versions(None)
    with z.writer() as txn:
        for i in range(60):
            txn.add(
                dns.rrset.from_text(f"h{i}", 3600, "in", "a", f"10.0.0.{i % 250 + 1}")
            )
        txn.update_serial(2, relative=False)
    query, _ = dns.xfr.make_query(z, serial=1)
    with z.reader() as current, z.reader(serial=1) as v1:
        messages = list(dns.xfr.Outbound(query, current, [v1], max_size=512))
    assert len(messages) > 1
    for message in messages:
        assert len(message.to_wire(multi=True)) <= 512
    old = dns.zone.from_text(ttl_base, "example.", zone_factory=dns.versioned.Zone)
    _apply_outbound(query, messages, old, serial=1)
    assert old == z


def test_outbound_ixfr_up_to_date():
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=4)
    with z.reader() as current:
        messages = list(dns.xfr.Outbound(query, current))
    assert len(messages) == 1
    assert len(messages[0].answer) == 1
    answer = messages[0].answer[0]
    assert answer.rdtype == dns.rdatatype.SOA
    assert answer[0].serial == 4
    current_zone = dns.zone.from_text(
        ixfr_expected, "example.", zone_factory=dns.versioned.Zone
    )
    _apply_outbound(query, messages, current_zone, serial=4)
    assert current_zone == z


def test_outbound_ixfr_client_ahead():
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=5)
    with z.reader() as current:
        messages = list(dns.xfr.Outbound(query, current))
    assert len(messages) == 1
    assert len(messages[0].answer) == 1
    answer = messages[0].answer[0]
    assert answer.rdtype == dns.rdatatype.SOA
    assert answer[0].serial == 4


def test_outbound_undefined_serial_order():
    z = _outbound_zone()
    # 4 and 4 + 2**31 are exactly half of the serial number space apart.
    query, _ = dns.xfr.make_query(z, serial=4 + 2**31)
    with z.reader() as current:
        with pytest.raises(dns.xfr.UndefinedSerialOrder):
            dns.xfr.Outbound(query, current)


wrap_base = """@ 3600 IN SOA foo bar 4294967293 2 3 4 5
@ 3600 IN NS ns1
ns1 3600 IN A 10.0.0.1
"""

wrap_expected = """@ 3600 IN SOA foo bar 1 2 3 4 5
@ 3600 IN NS ns1
ns1 3600 IN A 10.0.0.1
w2 3600 IN A 10.0.0.2
w3 3600 IN A 10.0.0.3
w4 3600 IN A 10.0.0.4
"""


def test_outbound_ixfr_serial_wraparound():
    z = dns.zone.from_text(wrap_base, "example.", zone_factory=dns.versioned.Zone)
    z.set_max_versions(None)
    for i, serial in enumerate((4294967294, 4294967295, 1)):
        with z.writer() as txn:
            txn.add(
                dns.rrset.from_text(f"w{i + 2}", 3600, "in", "a", f"10.0.0.{i + 2}")
            )
            txn.update_serial(serial, relative=False)
    query, _ = dns.xfr.make_query(z, serial=4294967293)
    with (
        z.reader() as current,
        z.reader(serial=4294967293) as v1,
        z.reader(serial=4294967294) as v2,
        z.reader(serial=4294967295) as v3,
    ):
        messages = list(dns.xfr.Outbound(query, current, [v1, v2, v3]))
    old = dns.zone.from_text(wrap_base, "example.", zone_factory=dns.versioned.Zone)
    _apply_outbound(query, messages, old, serial=4294967293)
    expected = dns.zone.from_text(wrap_expected, "example.")
    assert old == expected
    assert old.get_soa().serial == 1


def test_outbound_ixfr_ttl_only_change():
    z = dns.zone.from_text(ttl_base, "example.", zone_factory=dns.versioned.Zone)
    z.set_max_versions(None)
    with z.writer() as txn:
        txn.replace(dns.rrset.from_text("ns1", 7200, "in", "a", "10.0.0.1"))
        txn.update_serial(2, relative=False)
    query, _ = dns.xfr.make_query(z, serial=1)
    with z.reader() as current, z.reader(serial=1) as v1:
        messages = list(dns.xfr.Outbound(query, current, [v1]))
    # The sequence is SOA2, SOA1, delete A, SOA2, add A, SOA2.
    answers = [rrset for message in messages for rrset in message.answer]
    assert len(answers) == 6
    old = dns.zone.from_text(ttl_base, "example.", zone_factory=dns.versioned.Zone)
    _apply_outbound(query, messages, old, serial=1)
    rdataset = old.get_rdataset("ns1", "a")
    assert rdataset is not None
    assert rdataset.ttl == 7200
    assert _dump_zone(old) == _dump_zone(z)


def test_outbound_ixfr_history_pruned_fallback():
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=1)
    # The history starts at version 2; version 1 has been pruned.
    with z.reader() as current, z.reader(serial=2) as v2, z.reader(serial=3) as v3:
        messages = list(
            dns.xfr.Outbound(query, current, [v2, v3], fallback_to_axfr=True)
        )
    old = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    _apply_outbound(query, messages, old, serial=1)
    assert old == z


def test_outbound_ixfr_empty_history_fallback():
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=1)
    with z.reader() as current:
        messages = list(dns.xfr.Outbound(query, current, fallback_to_axfr=True))
    old = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    _apply_outbound(query, messages, old, serial=1)
    assert old == z


def test_outbound_ixfr_history_unavailable():
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=1)
    # The client's version is not in the history.
    with z.reader() as current, z.reader(serial=2) as v2, z.reader(serial=3) as v3:
        with pytest.raises(dns.xfr.IXFRHistoryUnavailable):
            dns.xfr.Outbound(query, current, [v2, v3])
    # There is no history at all.
    with z.reader() as current:
        with pytest.raises(dns.xfr.IXFRHistoryUnavailable):
            dns.xfr.Outbound(query, current)
    # The history is not consecutive (serials go backwards).
    query2, _ = dns.xfr.make_query(z, serial=2)
    with z.reader() as current, z.reader(serial=2) as v2, z.reader(serial=1) as v1:
        with pytest.raises(dns.xfr.IXFRHistoryUnavailable):
            dns.xfr.Outbound(query2, current, [v2, v1])


def test_outbound_axfr():
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=None)
    with z.reader() as current:
        messages = list(dns.xfr.Outbound(query, current))
    new = dns.versioned.Zone("example.")
    _apply_outbound(query, messages, new, rdtype=dns.rdatatype.AXFR)
    assert new == z


def test_outbound_ixfr_tsig():
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=1, keyring=keyring, keyname=keyname)
    query.to_wire()  # realize the query MAC, as a real server would have it
    with (
        z.reader() as current,
        z.reader(serial=1) as v1,
        z.reader(serial=2) as v2,
        z.reader(serial=3) as v3,
    ):
        messages = list(dns.xfr.Outbound(query, current, [v1, v2, v3], max_size=512))
    assert len(messages) > 1
    for message in messages:
        assert message.had_tsig
        assert len(message.to_wire(multi=True)) <= 512
    old = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    _apply_outbound(query, messages, old, serial=1, keyring=keyring)
    assert old == z


def test_outbound_record_too_big():
    z = dns.zone.from_text(ttl_base, "example.", zone_factory=dns.versioned.Zone)
    z.set_max_versions(None)
    big = " ".join('"' + "x" * 200 + '"' for _ in range(4))
    with z.writer() as txn:
        txn.add(dns.rrset.from_text("big", 3600, "in", "txt", big))
        txn.update_serial(2, relative=False)
    query, _ = dns.xfr.make_query(z, serial=1)
    with z.reader() as current, z.reader(serial=1) as v1:
        outbound = dns.xfr.Outbound(query, current, [v1], max_size=512)
        with pytest.raises(dns.exception.TooBig):
            list(outbound)


def test_outbound_bad_query():
    z = _outbound_zone()
    q = dns.message.make_query("example.", "a")
    with z.reader() as current:
        with pytest.raises(ValueError):
            dns.xfr.Outbound(q, current)
    # no question section
    q, _ = dns.xfr.make_query(z, serial=1)
    q.question = []
    with z.reader() as current:
        with pytest.raises(ValueError):
            dns.xfr.Outbound(q, current)


def test_outbound_wrong_origin():
    z = _outbound_zone()
    other = dns.versioned.Zone("other.")
    query, _ = dns.xfr.make_query(other, serial=1)
    with z.reader() as current:
        with pytest.raises(ValueError):
            dns.xfr.Outbound(query, current)


v2_text = """@ 3600 IN SOA foo bar 2 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.4
"""

v3_text = """@ 3600 IN SOA foo bar 3 2 3 4 5
@ 3600 IN NS ns1
@ 3600 IN NS ns2
ns1 3600 IN A 10.0.0.1
ns2 3600 IN A 10.0.0.4
ns3 3600 IN A 10.0.0.3
"""


def test_outbound_zone_sources():
    # The current zone and the history may be plain zones, not just
    # transactions.
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=1)
    history = [
        dns.zone.from_text(t, "example.", relativize=False)
        for t in (base, v2_text, v3_text)
    ]
    messages = list(dns.xfr.Outbound(query, z, history))
    old = dns.zone.from_text(base, "example.", zone_factory=dns.versioned.Zone)
    _apply_outbound(query, messages, old, serial=1)
    assert old == z


def test_outbound_bad_zone_sources():
    z = _outbound_zone()
    query, _ = dns.xfr.make_query(z, serial=1)
    # the current zone has no SOA
    with pytest.raises(ValueError):
        dns.xfr.Outbound(query, dns.zone.Zone("example."))
    # the current zone has no origin
    with pytest.raises(ValueError):
        dns.xfr.Outbound(query, dns.zone.Zone(None))
    # a history version has a different origin
    other = dns.zone.from_text(base, "other.")
    with pytest.raises(ValueError):
        dns.xfr.Outbound(query, z, [other])


def test_make_query_basic():
    z = dns.versioned.Zone("example.")
    q, s = dns.xfr.make_query(z)
    assert q.question[0].rdtype == dns.rdatatype.AXFR
    assert s is None
    q, s = dns.xfr.make_query(z, serial=None)
    assert q.question[0].rdtype == dns.rdatatype.AXFR
    assert s is None
    q, s = dns.xfr.make_query(z, serial=10)
    assert q.question[0].rdtype == dns.rdatatype.IXFR
    assert q.authority[0].rdtype == dns.rdatatype.SOA
    assert q.authority[0][0].serial == 10
    assert s == 10
    with z.writer() as txn:
        txn.add("@", 300, dns.rdata.from_text("in", "soa", ". . 1 2 3 4 5"))
    q, s = dns.xfr.make_query(z)
    assert q.question[0].rdtype == dns.rdatatype.IXFR
    assert q.authority[0].rdtype == dns.rdatatype.SOA
    assert q.authority[0][0].serial == 1
    assert s == 1
    q, s = dns.xfr.make_query(z, keyring=keyring, keyname=keyname)
    assert q.question[0].rdtype == dns.rdatatype.IXFR
    assert q.authority[0].rdtype == dns.rdatatype.SOA
    assert q.authority[0][0].serial == 1
    assert s == 1
    assert q.keyname == keyname


def test_make_query_bad_serial():
    z = dns.versioned.Zone("example.")
    with pytest.raises(ValueError):
        dns.xfr.make_query(z, serial="hi")
    with pytest.raises(ValueError):
        dns.xfr.make_query(z, serial=-1)
    with pytest.raises(ValueError):
        dns.xfr.make_query(z, serial=4294967296)


def test_extract_serial_from_query():
    z = dns.versioned.Zone("example.")
    q, s = dns.xfr.make_query(z)
    xs = dns.xfr.extract_serial_from_query(q)
    assert s is None
    assert s == xs
    q, s = dns.xfr.make_query(z, serial=10)
    xs = dns.xfr.extract_serial_from_query(q)
    assert s == 10
    assert s == xs
    q = dns.message.make_query("example", "a")
    with pytest.raises(ValueError):
        dns.xfr.extract_serial_from_query(q)


class XFRNanoNameserver(Server):
    def __init__(self):
        super().__init__(origin=dns.name.from_text("example"))

    def handle(self, request):
        try:
            if request.message.question[0].rdtype == dns.rdatatype.IXFR:
                text = ixfr
            else:
                text = axfr
            r = dns.message.from_text(text, one_rr_per_rrset=True, origin=self.origin)
            r.id = request.message.id
            return r
        except Exception:
            pass


@pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
def test_sync_inbound_xfr():
    with XFRNanoNameserver() as ns:
        zone = dns.versioned.Zone("example")
        dns.query.inbound_xfr(
            ns.tcp_address[0],
            zone,
            port=ns.tcp_address[1],
            udp_mode=dns.query.UDPMode.TRY_FIRST,
        )
        dns.query.inbound_xfr(
            ns.tcp_address[0],
            zone,
            port=ns.tcp_address[1],
            udp_mode=dns.query.UDPMode.TRY_FIRST,
        )
        expected = dns.zone.from_text(ixfr_expected, "example")
        assert zone == expected


async def async_inbound_xfr():
    with XFRNanoNameserver() as ns:
        zone = dns.versioned.Zone("example")
        await dns.asyncquery.inbound_xfr(
            ns.tcp_address[0],
            zone,
            port=ns.tcp_address[1],
            udp_mode=dns.query.UDPMode.TRY_FIRST,
        )
        await dns.asyncquery.inbound_xfr(
            ns.tcp_address[0],
            zone,
            port=ns.tcp_address[1],
            udp_mode=dns.query.UDPMode.TRY_FIRST,
        )
        expected = dns.zone.from_text(ixfr_expected, "example")
        assert zone == expected


@pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
def test_asyncio_inbound_xfr():
    dns.asyncbackend.set_default_backend("asyncio")

    async def run():
        await async_inbound_xfr()

    asyncio.run(run())


#
# We don't need to do this as it's all generic code, but
# just for extra caution we do it for each backend.
#

try:
    import trio

    @pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
    def test_trio_inbound_xfr():
        dns.asyncbackend.set_default_backend("trio")

        async def run():
            await async_inbound_xfr()

        trio.run(run)

except ImportError:
    pass


class UDPXFRNanoNameserver(Server):
    def __init__(self):
        super().__init__(origin=dns.name.from_text("example"))
        self.did_truncation = False

    def handle(self, request):
        try:
            if request.message.question[0].rdtype == dns.rdatatype.IXFR:
                if self.did_truncation:
                    text = ixfr
                else:
                    text = retry_tcp_ixfr
                    self.did_truncation = True
            else:
                text = axfr
            r = dns.message.from_text(text, one_rr_per_rrset=True, origin=self.origin)
            r.id = request.message.id
            return r
        except Exception:
            pass


@pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
def test_sync_retry_tcp_inbound_xfr():
    with UDPXFRNanoNameserver() as ns:
        zone = dns.versioned.Zone("example")
        dns.query.inbound_xfr(
            ns.tcp_address[0],
            zone,
            port=ns.tcp_address[1],
            udp_mode=dns.query.UDPMode.TRY_FIRST,
        )
        dns.query.inbound_xfr(
            ns.tcp_address[0],
            zone,
            port=ns.tcp_address[1],
            udp_mode=dns.query.UDPMode.TRY_FIRST,
        )
        expected = dns.zone.from_text(ixfr_expected, "example")
        assert zone == expected


async def udp_async_inbound_xfr():
    with UDPXFRNanoNameserver() as ns:
        zone = dns.versioned.Zone("example")
        await dns.asyncquery.inbound_xfr(
            ns.tcp_address[0],
            zone,
            port=ns.tcp_address[1],
            udp_mode=dns.query.UDPMode.TRY_FIRST,
        )
        await dns.asyncquery.inbound_xfr(
            ns.tcp_address[0],
            zone,
            port=ns.tcp_address[1],
            udp_mode=dns.query.UDPMode.TRY_FIRST,
        )
        expected = dns.zone.from_text(ixfr_expected, "example")
        assert zone == expected


@pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
def test_asyncio_retry_tcp_inbound_xfr():
    dns.asyncbackend.set_default_backend("asyncio")

    async def run():
        await udp_async_inbound_xfr()

    try:
        runner = asyncio.run
    except AttributeError:

        def old_runner(awaitable):
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(awaitable)

        runner = old_runner
    runner(run())


#
# The master's serial is older than ours, in a single-message IXFR response.
#
went_backwards_ixfr = """id 1
opcode QUERY
rcode NOERROR
flags AA
;QUESTION
example. IN IXFR
;ANSWER
@ 3600 IN SOA foo bar 5 2 3 4 5
"""

# Newer than what went_backwards_ixfr offers, so an IXFR from it goes backwards.
went_backwards_base = """@ 3600 IN SOA foo bar 6 2 3 4 5
@ 3600 IN NS ns1
"""


class WentBackwardsNanoNameserver(Server):
    def __init__(self):
        super().__init__(origin=dns.name.from_text("example"))

    def handle(self, request):
        try:
            r = dns.message.from_text(
                went_backwards_ixfr, one_rr_per_rrset=True, origin=self.origin
            )
            r.id = request.message.id
            return r
        except Exception:
            pass


def went_backwards_zone():
    return dns.zone.from_text(
        went_backwards_base, "example", zone_factory=dns.versioned.Zone
    )


def check_went_backwards_zone(zone):
    # Declining to raise ends the transfer without applying anything, so the
    # zone must be untouched.
    assert zone == dns.zone.from_text(went_backwards_base, "example")


#
# raise_on_serial_went_backwards has to reach dns.xfr.Inbound on both the UDP
# and the TCP path.  UDPMode.NEVER is TCP only; TRY_FIRST sends the IXFR over
# UDP first.
#
udp_modes = [dns.query.UDPMode.NEVER, dns.query.UDPMode.TRY_FIRST]


@pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
@pytest.mark.parametrize("udp_mode", udp_modes)
def test_sync_inbound_xfr_serial_went_backwards(udp_mode):
    with WentBackwardsNanoNameserver() as ns:
        where, port = ns.tcp_address
        with pytest.raises(dns.xfr.SerialWentBackwards):
            dns.query.inbound_xfr(
                where, went_backwards_zone(), port=port, udp_mode=udp_mode
            )
        zone = went_backwards_zone()
        dns.query.inbound_xfr(
            where,
            zone,
            port=port,
            udp_mode=udp_mode,
            raise_on_serial_went_backwards=False,
        )
        check_went_backwards_zone(zone)


async def async_inbound_xfr_serial_went_backwards(udp_mode):
    with WentBackwardsNanoNameserver() as ns:
        where, port = ns.tcp_address
        with pytest.raises(dns.xfr.SerialWentBackwards):
            await dns.asyncquery.inbound_xfr(
                where, went_backwards_zone(), port=port, udp_mode=udp_mode
            )
        zone = went_backwards_zone()
        await dns.asyncquery.inbound_xfr(
            where,
            zone,
            port=port,
            udp_mode=udp_mode,
            raise_on_serial_went_backwards=False,
        )
        check_went_backwards_zone(zone)


@pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
@pytest.mark.parametrize("udp_mode", udp_modes)
def test_asyncio_inbound_xfr_serial_went_backwards(udp_mode):
    dns.asyncbackend.set_default_backend("asyncio")

    async def run():
        await async_inbound_xfr_serial_went_backwards(udp_mode)

    asyncio.run(run())


try:
    import trio

    @pytest.mark.skipif(not _nanonameserver_available, reason="requires nanonameserver")
    @pytest.mark.parametrize("udp_mode", udp_modes)
    def test_trio_inbound_xfr_serial_went_backwards(udp_mode):
        dns.asyncbackend.set_default_backend("trio")

        async def run():
            await async_inbound_xfr_serial_went_backwards(udp_mode)

        trio.run(run)

except ImportError:
    pass
