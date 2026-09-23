# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for offline NSEC denial-of-existence validation (dns.nsec)."""

import unittest

import dns.dnssec
import dns.message
import dns.name
import dns.nsec
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY.NSEC
import dns.rrset
import dns.zone

if dns.dnssec._have_pyca:
    from cryptography.hazmat.primitives.asymmetric import ed25519

# A fixed validation time; all signatures are made valid around it.
NOW = 1700000000.0

ZONE_TEXT = """
$TTL 3600
@ SOA ns1 admin 1 2 3 4 5
@ NS ns1
ns1 A 10.0.0.1
www A 10.0.0.2
alias CNAME www
sub NS ns1.child.example.
*.wildcard A 10.0.0.3
zzz A 10.0.0.4
"""

OTHER_ZONE_TEXT = """
$TTL 3600
@ SOA ns1 admin 1 2 3 4 5
@ NS ns1
ns1 A 10.0.0.1
"""


def make_signed_zone(text, origin):
    zone = dns.zone.from_text(text, origin, relativize=False)
    private_key = ed25519.Ed25519PrivateKey.generate()
    dnskey = dns.dnssec.make_dnskey(
        private_key.public_key(), dns.dnssec.Algorithm.ED25519
    )
    dns.dnssec.sign_zone(
        zone, keys=[(private_key, dnskey)], inception=NOW - 100, expiration=NOW + 100000
    )
    dnskey_rdataset = zone.get_rdataset(zone.origin, dns.rdatatype.DNSKEY)
    keys = {zone.origin: dnskey_rdataset}
    return zone, keys


def make_response(zone, qname, qtype, rcode, nsec_owners, with_rrsig=True):
    query = dns.message.make_query(qname, qtype)
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    for owner in nsec_owners:
        nsec_rrset = zone.get_rrset(owner, dns.rdatatype.NSEC)
        response.authority.append(nsec_rrset)
        if with_rrsig:
            rrsig_rrset = zone.get_rrset(
                owner, dns.rdatatype.RRSIG, covers=dns.rdatatype.NSEC
            )
            response.authority.append(rrsig_rrset)
    return query, response


@unittest.skipUnless(dns.dnssec._have_pyca, "python cryptography not installed")
class NSECProofTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zone, cls.keys = make_signed_zone(ZONE_TEXT, "example.")
        cls.other_zone, cls.other_keys = make_signed_zone(
            OTHER_ZONE_TEXT, "other.example."
        )

    def validate(self, query, response, now=NOW, keys=None):
        if keys is None:
            keys = self.keys
        return dns.nsec.validate_negative_response(query, response, keys, now=now)

    def test_nxdomain_valid(self):
        # nope.example. is covered by the alias -> ns1 NSEC, and the
        # wildcard *.example. is covered by the apex NSEC.
        query, response = make_response(
            self.zone,
            "nope.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["alias.example.", "example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALID)
        self.assertEqual(len(proof.rrsets), 2)

    def test_nxdomain_valid_wraparound(self):
        # zzzz.example. falls in the wrap-around interval from the zone
        # tail (zzz.example.) back to the apex.
        query, response = make_response(
            self.zone,
            "zzzz.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["zzz.example.", "example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALID)

    def test_nxdomain_wildcard_not_excluded(self):
        # The qname is covered, but no NSEC excludes a matching wildcard.
        query, response = make_response(
            self.zone,
            "nope.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["alias.example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_nxdomain_wildcard_exists(self):
        # *.wildcard.example. exists, so NXDOMAIN for a name it would
        # synthesize cannot be proven.
        query, response = make_response(
            self.zone,
            "foo.wildcard.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["*.wildcard.example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_nxdomain_qname_exists(self):
        # www.example. exists; an NXDOMAIN claim is contradictory.
        query, response = make_response(
            self.zone,
            "www.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["www.example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_nxdomain_wildcard_query(self):
        # A direct query for a wildcard name needs no synthesis exclusion.
        query, response = make_response(
            self.zone,
            "*.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALID)

    def test_valid_signature_but_interval_does_not_cover(self):
        # The NSEC is cryptographically valid, but its interval does not
        # cover the qname, so the negative proof must fail.
        nsec_rrset = self.zone.get_rrset("www.example.", dns.rdatatype.NSEC)
        rrsig_rrset = self.zone.get_rrset(
            "www.example.", dns.rdatatype.RRSIG, covers=dns.rdatatype.NSEC
        )
        dns.dnssec.validate(nsec_rrset, rrsig_rrset, self.keys, now=NOW)
        query, response = make_response(
            self.zone,
            "nope.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["www.example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_tampered_nsec_fails_validation(self):
        # A modified NSEC with the original RRSIG fails cryptographic
        # validation.
        nsec_rrset = self.zone.get_rrset("alias.example.", dns.rdatatype.NSEC)
        original = nsec_rrset[0]
        tampered = dns.rdtypes.ANY.NSEC.NSEC(
            dns.rdataclass.IN, dns.rdatatype.NSEC, original.next, ()
        )
        tampered_rrset = dns.rrset.from_rdata(nsec_rrset.name, nsec_rrset.ttl, tampered)
        query, response = make_response(
            self.zone,
            "nope.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["alias.example.", "example."],
        )
        response.authority[0] = tampered_rrset
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALIDATION_FAILED)

    def test_expired_signature_fails_validation(self):
        query, response = make_response(
            self.zone,
            "nope.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["alias.example.", "example."],
        )
        proof = self.validate(query, response, now=NOW + 200000)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALIDATION_FAILED)

    def test_foreign_zone_signature_not_usable(self):
        # The other zone's NSEC is validly signed by its own key, but it
        # cannot prove anything about example.
        other_nsec = self.other_zone.get_rrset("other.example.", dns.rdatatype.NSEC)
        other_rrsig = self.other_zone.get_rrset(
            "other.example.", dns.rdatatype.RRSIG, covers=dns.rdatatype.NSEC
        )
        dns.dnssec.validate(other_nsec, other_rrsig, self.other_keys, now=NOW)
        query = dns.message.make_query("nope.example.", "A")
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        response.authority.append(other_nsec)
        response.authority.append(other_rrsig)
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_qname_out_of_zone(self):
        query = dns.message.make_query("nope.unrelated.", "A")
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        for owner in ["alias.example.", "example."]:
            response.authority.append(self.zone.get_rrset(owner, dns.rdatatype.NSEC))
            response.authority.append(
                self.zone.get_rrset(
                    owner, dns.rdatatype.RRSIG, covers=dns.rdatatype.NSEC
                )
            )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_no_nsec_in_response(self):
        query = dns.message.make_query("nope.example.", "A")
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_nsec_without_rrsig(self):
        query, response = make_response(
            self.zone,
            "nope.example.",
            "A",
            dns.rcode.NXDOMAIN,
            ["alias.example.", "example."],
            with_rrsig=False,
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_nodata_valid(self):
        query, response = make_response(
            self.zone, "www.example.", "MX", dns.rcode.NOERROR, ["www.example."]
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALID)
        self.assertEqual(len(proof.rrsets), 1)

    def test_nodata_qtype_present(self):
        query, response = make_response(
            self.zone, "www.example.", "A", dns.rcode.NOERROR, ["www.example."]
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_nodata_cname_present(self):
        # alias.example. has a CNAME, so NODATA for another type cannot
        # be proven.
        query, response = make_response(
            self.zone, "alias.example.", "A", dns.rcode.NOERROR, ["alias.example."]
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_nodata_at_delegation_ds_absent(self):
        # The NSEC at a delegation proves the absence of DS (an insecure
        # delegation).
        query, response = make_response(
            self.zone, "sub.example.", "DS", dns.rcode.NOERROR, ["sub.example."]
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALID)

    def test_nodata_at_delegation_other_type(self):
        # The NSEC at a delegation says nothing about other types.
        query, response = make_response(
            self.zone, "sub.example.", "A", dns.rcode.NOERROR, ["sub.example."]
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_wildcard_nodata_valid(self):
        # foo.wildcard.example. does not exist but matches the wildcard
        # *.wildcard.example., which has no MX.  The wildcard's own NSEC
        # also covers the qname.
        query, response = make_response(
            self.zone,
            "foo.wildcard.example.",
            "MX",
            dns.rcode.NOERROR,
            ["*.wildcard.example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALID)
        self.assertEqual(len(proof.rrsets), 1)

    def test_wildcard_nodata_qtype_present(self):
        query, response = make_response(
            self.zone,
            "foo.wildcard.example.",
            "A",
            dns.rcode.NOERROR,
            ["*.wildcard.example."],
        )
        proof = self.validate(query, response)
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.INSUFFICIENT)

    def test_question_tuple(self):
        query, response = make_response(
            self.zone, "www.example.", "MX", dns.rcode.NOERROR, ["www.example."]
        )
        proof = self.validate(
            (dns.name.from_text("www.example."), dns.rdatatype.MX), response
        )
        self.assertEqual(proof.status, dns.nsec.NegativeProofStatus.VALID)

    def test_statuses_are_distinguishable(self):
        statuses = list(dns.nsec.NegativeProofStatus)
        self.assertEqual(len(statuses), 3)
        self.assertEqual(len(set(statuses)), 3)


if __name__ == "__main__":
    unittest.main()
