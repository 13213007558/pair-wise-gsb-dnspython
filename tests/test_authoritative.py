# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import unittest

import dns.authoritative
import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.zone

ZONE_TEXT = """
$ORIGIN example.test.
$TTL 3600
@           SOA ns1 admin 1 7200 3600 1209600 300
@           NS ns1
ns1         A 192.0.2.1
www         A 192.0.2.10
www         AAAA 2001:db8::10
onlya       A 192.0.2.11
*.wild      A 192.0.2.100
x.ent.wild  A 192.0.2.101
sub         NS ns1.sub
sub         NS ns2
ns1.sub     A 192.0.2.200
ns1.sub     AAAA 2001:db8::200
ns2         A 192.0.2.201
dnameat     DNAME dtarget
*.dwild     DNAME dtarget
*.cwild     CNAME www
www2        CNAME www
alias       CNAME target.other.example.
dangle      CNAME nosuch
subalias    CNAME www.sub
loop1       CNAME loop2
loop2       CNAME loop1
chain1      CNAME chain2
chain2      CNAME chain3
chain3      A 192.0.2.30
"""

ORIGIN = dns.name.from_text("example.test.")


def name(text):
    return dns.name.from_text(text, ORIGIN)


class AuthoritativeTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zone = dns.zone.from_text(ZONE_TEXT, origin="example.test.")

    def respond(self, qname, qtype="A", max_cname_chain=16, **kw):
        kw.setdefault("flags", 0)
        q = dns.message.make_query(qname, qtype, **kw)
        r = dns.authoritative.answer(self.zone, q, max_cname_chain)
        # Verify the response survives a wire format round-trip.
        return dns.message.from_wire(r.to_wire())

    def test_simple_a(self):
        r = self.respond("www.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 1)
        self.assertEqual(r.answer[0].name, name("www"))
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.A)
        self.assertEqual(r.answer[0][0].address, "192.0.2.10")

    def test_simple_aaaa(self):
        r = self.respond("www.example.test.", "AAAA")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 1)
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.AAAA)
        self.assertEqual(r.answer[0][0].address, "2001:db8::10")

    def test_question_and_id_preserved(self):
        q = dns.message.make_query("www.example.test.", "A", flags=0, id=1234)
        r = dns.message.from_wire(
            dns.authoritative.answer(self.zone, q).to_wire()
        )
        self.assertEqual(r.id, 1234)
        self.assertEqual(len(r.question), 1)
        self.assertEqual(r.question[0].name, name("www"))
        self.assertEqual(r.question[0].rdtype, dns.rdatatype.A)

    def test_wildcard(self):
        r = self.respond("foo.wild.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 1)
        # The answer is synthesized with the query name as owner.
        self.assertEqual(r.answer[0].name, name("foo.wild"))
        self.assertEqual(r.answer[0][0].address, "192.0.2.100")

    def test_wildcard_multi_label(self):
        r = self.respond("a.b.wild.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 1)
        self.assertEqual(r.answer[0].name, name("a.b.wild"))
        self.assertEqual(r.answer[0][0].address, "192.0.2.100")

    def test_empty_non_terminal_is_nodata(self):
        # ent.wild exists only as an empty non-terminal, so it must not
        # match the *.wild wildcard and must not be NXDOMAIN either.
        r = self.respond("ent.wild.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(len(r.authority), 1)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.SOA)
        self.assertEqual(r.authority[0].name, ORIGIN)

    def test_empty_non_terminal_below_wildcard(self):
        # wild itself is also an empty non-terminal.
        r = self.respond("wild.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.SOA)

    def test_below_empty_non_terminal_is_nxdomain(self):
        r = self.respond("y.ent.wild.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.SOA)

    def test_nxdomain(self):
        r = self.respond("nosuch.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(len(r.authority), 1)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.SOA)
        # The authority TTL is the negative caching TTL.
        self.assertEqual(r.authority[0].ttl, 300)

    def test_nodata(self):
        r = self.respond("onlya.example.test.", "AAAA")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(len(r.authority), 1)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.SOA)
        self.assertEqual(r.authority[0].ttl, 300)

    def test_referral(self):
        r = self.respond("www.sub.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertFalse(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(len(r.authority), 1)
        ns = r.authority[0]
        self.assertEqual(ns.name, name("sub"))
        self.assertEqual(ns.rdtype, dns.rdatatype.NS)
        targets = {str(rd.target) for rd in ns}
        self.assertEqual(
            targets, {"ns1.sub.example.test.", "ns2.example.test."}
        )
        # Only in-bailiwick glue is included.
        glue = {rrset.rdtype: rrset for rrset in r.additional}
        self.assertEqual(
            set(glue), {dns.rdatatype.A, dns.rdatatype.AAAA}
        )
        for rrset in glue.values():
            self.assertEqual(rrset.name, name("ns1.sub"))
        self.assertEqual(glue[dns.rdatatype.A][0].address, "192.0.2.200")
        self.assertEqual(
            glue[dns.rdatatype.AAAA][0].address, "2001:db8::200"
        )

    def test_referral_at_cut(self):
        r = self.respond("sub.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertFalse(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.NS)

    def test_referral_deep(self):
        # We do not answer across the delegation, even for names that
        # do not exist below the cut.
        r = self.respond("a.b.sub.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertFalse(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(r.authority[0].name, name("sub"))
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.NS)

    def test_glue_name_gets_referral(self):
        # The address of ns1.sub is glue below the zone cut, so
        # querying for it yields a referral, not an authoritative
        # answer.
        r = self.respond("ns1.sub.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertFalse(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.NS)

    def test_cname_chased_in_zone(self):
        r = self.respond("www2.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.AA)
        self.assertEqual(len(r.answer), 2)
        self.assertEqual(r.answer[0].name, name("www2"))
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.CNAME)
        self.assertEqual(str(r.answer[0][0].target), "www.example.test.")
        self.assertEqual(r.answer[1].name, name("www"))
        self.assertEqual(r.answer[1].rdtype, dns.rdatatype.A)
        self.assertEqual(r.answer[1][0].address, "192.0.2.10")

    def test_cname_query(self):
        r = self.respond("www2.example.test.", "CNAME")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 1)
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.CNAME)

    def test_cname_cross_zone_stops(self):
        r = self.respond("alias.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.AA)
        # The chain is kept, but the cross-zone target is not chased.
        self.assertEqual(len(r.answer), 1)
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.CNAME)
        self.assertEqual(
            str(r.answer[0][0].target), "target.other.example."
        )

    def test_cname_below_delegation_stops(self):
        r = self.respond("subalias.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertTrue(r.flags & dns.flags.AA)
        # We do not answer across the delegation for the target.
        self.assertEqual(len(r.answer), 1)
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.CNAME)
        self.assertEqual(str(r.answer[0][0].target), "www.sub.example.test.")

    def test_cname_to_nxdomain(self):
        r = self.respond("dangle.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(len(r.answer), 1)
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.CNAME)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.SOA)

    def test_cname_chain(self):
        r = self.respond("chain1.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 3)
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.CNAME)
        self.assertEqual(r.answer[1].rdtype, dns.rdatatype.CNAME)
        self.assertEqual(r.answer[2].rdtype, dns.rdatatype.A)
        self.assertEqual(r.answer[2][0].address, "192.0.2.30")

    def test_wildcard_cname(self):
        r = self.respond("foo.cwild.example.test.")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 2)
        self.assertEqual(r.answer[0].name, name("foo.cwild"))
        self.assertEqual(r.answer[0].rdtype, dns.rdatatype.CNAME)
        self.assertEqual(str(r.answer[0][0].target), "www.example.test.")
        self.assertEqual(r.answer[1].name, name("www"))
        self.assertEqual(r.answer[1][0].address, "192.0.2.10")

    def test_cname_loop(self):
        q = dns.message.make_query("loop1.example.test.", "A", flags=0)
        with self.assertRaises(dns.authoritative.CnameLoop):
            dns.authoritative.answer(self.zone, q)

    def test_cname_chain_too_long(self):
        q = dns.message.make_query("chain1.example.test.", "A", flags=0)
        with self.assertRaises(dns.authoritative.CnameChainTooLong):
            dns.authoritative.answer(self.zone, q, max_cname_chain=1)

    def test_out_of_zone(self):
        r = self.respond("other.example.")
        self.assertEqual(r.rcode(), dns.rcode.REFUSED)
        self.assertFalse(r.flags & dns.flags.AA)

    def test_recursion_requested(self):
        # make_query sets RD by default.
        r = self.respond("www.example.test.", flags=dns.flags.RD)
        self.assertEqual(r.rcode(), dns.rcode.REFUSED)

    def test_unsupported_type(self):
        r = self.respond("www.example.test.", "MX")
        self.assertEqual(r.rcode(), dns.rcode.NOTIMP)

    def test_dname_type_not_supported(self):
        r = self.respond("www.example.test.", "DNAME")
        self.assertEqual(r.rcode(), dns.rcode.NOTIMP)

    def test_unsupported_class(self):
        r = self.respond("www.example.test.", "A", rdclass="CH")
        self.assertEqual(r.rcode(), dns.rcode.NOTIMP)

    def test_dnssec_not_supported(self):
        r = self.respond("www.example.test.", want_dnssec=True)
        self.assertEqual(r.rcode(), dns.rcode.NOTIMP)

    def test_cd_bit_not_supported(self):
        r = self.respond("www.example.test.", flags=dns.flags.CD)
        self.assertEqual(r.rcode(), dns.rcode.NOTIMP)

    def test_non_query_opcode(self):
        q = dns.message.make_query("www.example.test.", "A", flags=0)
        q.set_opcode(dns.opcode.UPDATE)
        r = dns.authoritative.answer(self.zone, q)
        self.assertEqual(r.rcode(), dns.rcode.NOTIMP)

    def test_no_question(self):
        q = dns.message.Message(id=1)
        r = dns.authoritative.answer(self.zone, q)
        self.assertEqual(r.rcode(), dns.rcode.FORMERR)

    def test_cname_query_nodata(self):
        r = self.respond("www.example.test.", "CNAME")
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 0)
        self.assertEqual(r.authority[0].rdtype, dns.rdatatype.SOA)

    def test_dname_record_not_supported(self):
        # A DNAME at the exact name, at an ancestor, and at a wildcard
        # are all out of scope.
        for qname in (
            "dnameat.example.test.",
            "x.dnameat.example.test.",
            "foo.dwild.example.test.",
        ):
            r = self.respond(qname)
            self.assertEqual(r.rcode(), dns.rcode.NOTIMP)

    def test_zone_without_origin(self):
        q = dns.message.make_query("www.example.test.", "A", flags=0)
        with self.assertRaises(ValueError):
            dns.authoritative.answer(dns.zone.Zone(None), q)

    def test_negative_max_cname_chain(self):
        q = dns.message.make_query("www.example.test.", "A", flags=0)
        with self.assertRaises(ValueError):
            dns.authoritative.answer(self.zone, q, max_cname_chain=-1)

    def test_zone_without_soa(self):
        zone = dns.zone.from_text(
            "@ 300 IN A 192.0.2.1\n", origin="example.test.", check_origin=False
        )
        q = dns.message.make_query("nosuch.example.test.", "A", flags=0)
        r = dns.message.from_wire(dns.authoritative.answer(zone, q).to_wire())
        self.assertEqual(r.rcode(), dns.rcode.NXDOMAIN)
        self.assertEqual(len(r.authority), 0)

    def test_non_relativized_zone(self):
        zone = dns.zone.from_text(
            ZONE_TEXT, origin="example.test.", relativize=False
        )
        q = dns.message.make_query("www2.example.test.", "A", flags=0)
        r = dns.message.from_wire(dns.authoritative.answer(zone, q).to_wire())
        self.assertEqual(r.rcode(), dns.rcode.NOERROR)
        self.assertEqual(len(r.answer), 2)
        self.assertEqual(r.answer[1][0].address, "192.0.2.10")


if __name__ == "__main__":
    unittest.main()
