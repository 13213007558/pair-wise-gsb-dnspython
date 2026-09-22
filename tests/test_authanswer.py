"""Tests for tests/authanswer.py, the authoritative answer function."""

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.zone
import pytest

from tests.authanswer import answer_query

# The zone has:
# - a wildcard *.example.test with A and AAAA
# - an empty non-terminal leaf.example.test (only deep.leaf exists)
# - a delegated subzone sub.example.test with in-bailiwick glue
#   (ns1.sub.example.test) and an out-of-bailiwick nameserver
#   (ns2.example.test, whose address is in-zone but is not glue)
# - occluded data below the delegation (occluded.sub.example.test)
# - an in-zone CNAME (www), a cross-zone CNAME (out), CNAME loops
#   (loop-a/loop-b, self), and a multi-hop chain (chain1..chain3)
ZONE_TEXT = """
$ORIGIN example.test.
@           300 IN SOA   ns1.example.test. admin.example.test. 1 3600 600 86400 300
@           300 IN NS    ns1.example.test.
ns1         300 IN A     192.0.2.1
ns1         300 IN AAAA  2001:db8::1
*           300 IN A     192.0.2.100
*           300 IN AAAA  2001:db8::100
plain       300 IN A     192.0.2.10
plain       300 IN AAAA  2001:db8::10
only-a      300 IN A     192.0.2.11
www         300 IN CNAME plain
out         300 IN CNAME target.other-zone.example.
loop-a      300 IN CNAME loop-b
loop-b      300 IN CNAME loop-a
self        300 IN CNAME self
chain1      300 IN CNAME chain2
chain2      300 IN CNAME chain3
chain3      300 IN A     192.0.2.12
deep.leaf   300 IN A     192.0.2.20
sub         300 IN NS    ns1.sub
sub         300 IN NS    ns2.example.test.
ns1.sub     300 IN A     192.0.2.53
ns1.sub     300 IN AAAA  2001:db8::53
occluded.sub 300 IN A    192.0.2.99
ns2         300 IN A     192.0.2.2
"""

ORIGIN = dns.name.from_text("example.test.")


@pytest.fixture(scope="module")
def zone():
    return dns.zone.from_text(ZONE_TEXT, origin=ORIGIN, relativize=False)


def ask(zone, qname, qtype, max_cname_chain=None, **make_query_kwargs):
    """Ask the zone a question and return the wire-format round-tripped
    response, so assertions check what a client would actually receive."""
    kwargs = {"flags": 0}
    kwargs.update(make_query_kwargs)
    query = dns.message.make_query(qname, qtype, **kwargs)
    if max_cname_chain is None:
        response = answer_query(zone, query)
    else:
        response = answer_query(zone, query, max_cname_chain=max_cname_chain)
    return dns.message.from_wire(response.to_wire()), query


def rrset_texts(section):
    return sorted(rrset.to_text() for rrset in section)


def test_exact_a(zone):
    response, query = ask(zone, "plain.example.test.", "A")
    assert response.id == query.id
    assert response.flags & dns.flags.AA
    assert not response.flags & dns.flags.RA
    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.question) == 1
    assert response.question[0].name == dns.name.from_text("plain.example.test.")
    assert len(response.answer) == 1
    rrset = response.answer[0]
    assert rrset.name == dns.name.from_text("plain.example.test.")
    assert rrset.rdclass == dns.rdataclass.IN
    assert rrset.rdtype == dns.rdatatype.A
    assert rrset.ttl == 300
    assert [rd.address for rd in rrset] == ["192.0.2.10"]
    assert response.authority == []
    assert response.additional == []


def test_exact_aaaa(zone):
    response, _ = ask(zone, "plain.example.test.", "AAAA")
    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.answer) == 1
    rrset = response.answer[0]
    assert rrset.name == dns.name.from_text("plain.example.test.")
    assert rrset.rdtype == dns.rdatatype.AAAA
    assert [rd.address for rd in rrset] == ["2001:db8::10"]


def test_nodata(zone):
    # only-a.example.test exists, but has no AAAA.
    response, _ = ask(zone, "only-a.example.test.", "AAAA")
    assert response.rcode() == dns.rcode.NOERROR
    assert response.flags & dns.flags.AA
    assert response.answer == []
    assert len(response.authority) == 1
    soa = response.authority[0]
    assert soa.name == ORIGIN
    assert soa.rdtype == dns.rdatatype.SOA
    assert response.additional == []


def test_nxdomain_below_empty_non_terminal(zone):
    # zz.leaf.example.test does not exist; its closest encloser is the
    # empty non-terminal leaf.example.test, and *.leaf.example.test does
    # not exist, so this is NXDOMAIN, not a *.example.test match.
    response, _ = ask(zone, "zz.leaf.example.test.", "A")
    assert response.rcode() == dns.rcode.NXDOMAIN
    assert response.flags & dns.flags.AA
    assert response.answer == []
    assert len(response.authority) == 1
    assert response.authority[0].rdtype == dns.rdatatype.SOA
    assert response.authority[0].name == ORIGIN


def test_wildcard_synthesis(zone):
    response, _ = ask(zone, "whatever.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert response.flags & dns.flags.AA
    assert len(response.answer) == 1
    rrset = response.answer[0]
    # The owner name is the qname, not the wildcard.
    assert rrset.name == dns.name.from_text("whatever.example.test.")
    assert rrset.rdtype == dns.rdatatype.A
    assert [rd.address for rd in rrset] == ["192.0.2.100"]


def test_wildcard_synthesis_aaaa(zone):
    response, _ = ask(zone, "anything-at-all.example.test.", "AAAA")
    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.answer) == 1
    rrset = response.answer[0]
    assert rrset.name == dns.name.from_text("anything-at-all.example.test.")
    assert [rd.address for rd in rrset] == ["2001:db8::100"]


def test_empty_non_terminal_blocks_wildcard(zone):
    # leaf.example.test is an empty non-terminal: it exists, so the
    # wildcard does not match it; the result is NODATA, not the
    # wildcard's A record.
    response, _ = ask(zone, "leaf.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert response.flags & dns.flags.AA
    assert response.answer == []
    assert len(response.authority) == 1
    assert response.authority[0].rdtype == dns.rdatatype.SOA


def test_referral_below_cut(zone):
    response, _ = ask(zone, "www.sub.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert not response.flags & dns.flags.AA
    assert response.answer == []
    assert len(response.authority) == 1
    ns = response.authority[0]
    assert ns.name == dns.name.from_text("sub.example.test.")
    assert ns.rdtype == dns.rdatatype.NS
    assert sorted(str(rd.target) for rd in ns) == [
        "ns1.sub.example.test.",
        "ns2.example.test.",
    ]
    # Only in-bailiwick glue: ns1.sub.example.test A and AAAA.  The
    # address of ns2.example.test is in the zone but is not glue.
    assert rrset_texts(response.additional) == [
        "ns1.sub.example.test. 300 IN A 192.0.2.53",
        "ns1.sub.example.test. 300 IN AAAA 2001:db8::53",
    ]


def test_referral_at_cut(zone):
    response, _ = ask(zone, "sub.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert not response.flags & dns.flags.AA
    assert response.answer == []
    assert len(response.authority) == 1
    assert response.authority[0].rdtype == dns.rdatatype.NS
    assert response.authority[0].name == dns.name.from_text("sub.example.test.")


def test_occluded_data_below_cut_is_not_served(zone):
    # occluded.sub.example.test has an A record in the zone, but it is
    # below the delegation point and must not be answered.
    response, _ = ask(zone, "occluded.sub.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert not response.flags & dns.flags.AA
    assert response.answer == []
    assert len(response.authority) == 1
    assert response.authority[0].rdtype == dns.rdatatype.NS


def test_wildcard_does_not_cross_cut(zone):
    # The wildcard must not synthesize an answer below the delegation.
    response, _ = ask(zone, "random.sub.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert not response.flags & dns.flags.AA
    assert response.answer == []
    assert len(response.authority) == 1
    assert response.authority[0].rdtype == dns.rdatatype.NS


def test_cname_chased_within_zone(zone):
    response, _ = ask(zone, "www.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert response.flags & dns.flags.AA
    assert len(response.answer) == 2
    cname, a = response.answer
    assert cname.name == dns.name.from_text("www.example.test.")
    assert cname.rdtype == dns.rdatatype.CNAME
    assert cname[0].target == dns.name.from_text("plain.example.test.")
    assert a.name == dns.name.from_text("plain.example.test.")
    assert a.rdtype == dns.rdatatype.A
    assert [rd.address for rd in a] == ["192.0.2.10"]


def test_cname_query_type(zone):
    response, _ = ask(zone, "www.example.test.", "CNAME")
    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.answer) == 1
    cname = response.answer[0]
    assert cname.rdtype == dns.rdatatype.CNAME
    assert cname[0].target == dns.name.from_text("plain.example.test.")


def test_cross_zone_cname_stops(zone):
    response, _ = ask(zone, "out.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert response.flags & dns.flags.AA
    # The chain is kept, but the out-of-zone target is not chased.
    assert len(response.answer) == 1
    cname = response.answer[0]
    assert cname.name == dns.name.from_text("out.example.test.")
    assert cname.rdtype == dns.rdatatype.CNAME
    assert cname[0].target == dns.name.from_text("target.other-zone.example.")
    assert response.authority == []


def test_cname_loop(zone):
    for name in ("loop-a.example.test.", "loop-b.example.test.", "self.example.test."):
        response, _ = ask(zone, name, "A")
        assert response.rcode() == dns.rcode.SERVFAIL
        assert response.answer == []


def test_cname_chain(zone):
    response, _ = ask(zone, "chain1.example.test.", "A")
    assert response.rcode() == dns.rcode.NOERROR
    assert len(response.answer) == 3
    cname1, cname2, a = response.answer
    assert cname1.name == dns.name.from_text("chain1.example.test.")
    assert cname1[0].target == dns.name.from_text("chain2.example.test.")
    assert cname2.name == dns.name.from_text("chain2.example.test.")
    assert cname2[0].target == dns.name.from_text("chain3.example.test.")
    assert a.name == dns.name.from_text("chain3.example.test.")
    assert [rd.address for rd in a] == ["192.0.2.12"]


def test_cname_chain_too_long(zone):
    response, _ = ask(zone, "chain1.example.test.", "A", max_cname_chain=1)
    assert response.rcode() == dns.rcode.SERVFAIL
    assert response.answer == []


def test_unsupported_qtype(zone):
    response, _ = ask(zone, "plain.example.test.", "TXT")
    assert response.rcode() == dns.rcode.NOTIMP
    assert response.answer == []


def test_dnssec_qtype_not_supported(zone):
    response, _ = ask(zone, "example.test.", "DNSKEY")
    assert response.rcode() == dns.rcode.NOTIMP


def test_dname_qtype_not_supported(zone):
    response, _ = ask(zone, "example.test.", "DNAME")
    assert response.rcode() == dns.rcode.NOTIMP


def test_recursion_desired_refused(zone):
    response, _ = ask(zone, "plain.example.test.", "A", flags=dns.flags.RD)
    assert response.rcode() == dns.rcode.REFUSED
    assert not response.flags & dns.flags.RA


def test_out_of_zone_refused(zone):
    response, _ = ask(zone, "other-zone.example.", "A")
    assert response.rcode() == dns.rcode.REFUSED


def test_other_class_refused(zone):
    response, _ = ask(zone, "plain.example.test.", "A", rdclass=dns.rdataclass.CH)
    assert response.rcode() == dns.rcode.REFUSED


def test_non_query_opcode_notimp(zone):
    query = dns.message.make_query("plain.example.test.", "A", flags=0)
    query.set_opcode(dns.opcode.STATUS)
    response = dns.message.from_wire(answer_query(zone, query).to_wire())
    assert response.rcode() == dns.rcode.NOTIMP


def test_question_and_id_preserved(zone):
    response, query = ask(zone, "plain.example.test.", "A")
    assert response.id == query.id
    assert len(response.question) == 1
    question = response.question[0]
    assert question.name == dns.name.from_text("plain.example.test.")
    assert question.rdtype == dns.rdatatype.A
    assert question.rdclass == dns.rdataclass.IN
