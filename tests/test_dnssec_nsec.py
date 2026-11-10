# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for traditional NSEC denial-of-existence proof validation."""

import unittest
from typing import cast

import dns.dnssec
import dns.message
import dns.name
import dns.rdatatype
import dns.rrset
import dns.zone
from dns.exception import IncompleteProof, NSEC3Unsupported, ValidationFailure
from dns.rdtypes.dnskeybase import Flag

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:  # pragma: no cover
    ed25519 = None

# A small zone exercising every NSEC negative-proof shape:
#  - ordinary exact names (host, mail, ...)
#  - an empty non-terminal (ent.sub exists only because ent.sub.leaf does)
#  - a wildcard (*.wild)
#  - a last NSEC that wraps around to the apex (zzz -> example)
ZONE_TEXT = """
example. 3600 IN SOA ns1.example. hostmaster.example. 1 2 3 4 5
example. 3600 IN NS ns1.example.
ns1.example. 3600 IN A 10.0.0.1
host.example. 3600 IN A 10.0.0.9
host.example. 3600 IN MX 0 mail.example.
ent.sub.example. 3600 IN TXT "ent"
*.wild.example. 3600 IN A 10.0.0.7
mail.example. 3600 IN A 10.0.0.2
zzz.example. 3600 IN A 10.0.0.3
"""

ORIGIN = dns.name.from_text("example.")
INCEPTION = 1000000000
EXPIRATION = 1000003600
NOW = 1000001000


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class NSECProofTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.zone = dns.zone.from_text(ZONE_TEXT, "example.", relativize=False)
        cls.private_key = ed25519.Ed25519PrivateKey.generate()
        cls.dnskey = dns.dnssec.make_dnskey(
            public_key=cls.private_key.public_key(),
            algorithm=dns.dnssec.ED25519,
            flags=Flag.ZONE,
        )
        dns.dnssec.sign_zone(
            cls.zone,
            keys=[(cls.private_key, cls.dnskey)],
            inception=INCEPTION,
            expiration=EXPIRATION,
        )
        cls.keys = {ORIGIN: cls.zone.find_rdataset(ORIGIN, dns.rdatatype.DNSKEY)}
        # A second, independently signed zone used to prove that valid
        # foreign-zone material cannot be stitched into a proof.
        cls.other_zone = dns.zone.from_text(
            "other. 3600 IN SOA ns.other. hm.other. 1 2 3 4 5\n"
            "other. 3600 IN NS ns.other.\n"
            "ns.other. 3600 IN A 10.1.0.1\n",
            "other.",
            relativize=False,
        )
        cls.other_private = ed25519.Ed25519PrivateKey.generate()
        cls.other_key = dns.dnssec.make_dnskey(
            cls.other_private.public_key(), dns.dnssec.ED25519, flags=Flag.ZONE
        )
        dns.dnssec.sign_zone(
            cls.other_zone,
            keys=[(cls.other_private, cls.other_key)],
            inception=INCEPTION,
            expiration=EXPIRATION,
        )

    def _nsec(self, name):
        return self.zone.find_rrset(dns.name.from_text(name), dns.rdatatype.NSEC)

    def _nsec_rrsig(self, name):
        return self.zone.find_rrset(
            dns.name.from_text(name),
            dns.rdatatype.RRSIG,
            covers=dns.rdatatype.NSEC,
        )

    def _materials(self, names):
        nsec_rrsets = [self._nsec(name) for name in names]
        rrsig_rrsets = [self._nsec_rrsig(name) for name in names]
        return nsec_rrsets, rrsig_rrsets

    def _validate(self, qname, qtype, names, **kwargs):
        nsec_rrsets, rrsig_rrsets = self._materials(names)
        return dns.dnssec.validate_nsec_negative_proof(
            dns.name.from_text(qname),
            qtype,
            self.keys,
            nsec_rrsets,
            rrsig_rrsets,
            now=kwargs.pop("now", NOW),
            **kwargs,
        )

    # ------------------------------------------------------------------
    # Successful proofs
    # ------------------------------------------------------------------

    def test_exact_name_nodata(self):
        proof = self._validate("host.example.", "TXT", ["host.example."])
        self.assertTrue(proof.is_nodata)
        self.assertEqual(proof.zone, ORIGIN)
        self.assertEqual(proof.closest_encloser, dns.name.from_text("host.example."))
        self.assertEqual(len(proof.evidence), 1)
        entry = proof.evidence[0]
        self.assertEqual(entry.roles, (dns.dnssec.NSECRole.EXACT_NAME,))
        self.assertEqual(entry.name, dns.name.from_text("host.example."))

    def test_exact_name_nodata_empty_non_terminal(self):
        # ent.sub is an empty non-terminal: its NSEC exists but lists no
        # ordinary application types besides the NSEC machinery.
        proof = self._validate("ent.sub.example.", "A", ["ent.sub.example."])
        self.assertTrue(proof.is_nodata)
        nsec = proof.evidence[0].nsec
        self.assertFalse(dns.dnssec._nsec_has_type(nsec, dns.rdatatype.A))
        self.assertTrue(dns.dnssec._nsec_has_type(nsec, dns.rdatatype.NSEC))

    def test_nxdomain_simple(self):
        # mail -> ns1 covers both nomail.example and *.example, so two
        # NSECs suffice (RFC 7129 section 5.2).
        proof = self._validate("nomail.example.", "A", ["example.", "mail.example."])
        self.assertTrue(proof.is_nxdomain)
        self.assertEqual(proof.closest_encloser, ORIGIN)
        roles = {entry.name: set(entry.roles) for entry in proof.evidence}
        self.assertEqual(
            roles[dns.name.from_text("example.")],
            {
                dns.dnssec.NSECRole.CLOSEST_ENCLOSER,
                dns.dnssec.NSECRole.WILDCARD_POSSIBILITY,
            },
        )
        self.assertEqual(
            roles[dns.name.from_text("mail.example.")],
            {dns.dnssec.NSECRole.NEXT_CLOSER},
        )

    def test_nxdomain_under_empty_non_terminal(self):
        proof = self._validate(
            "x.ent.sub.example.",
            "A",
            ["ent.sub.example.", "*.wild.example."],
        )
        self.assertTrue(proof.is_nxdomain)
        self.assertEqual(proof.closest_encloser, dns.name.from_text("ent.sub.example."))
        # The ent.sub NSEC interval covers x.ent.sub, *.ent.sub and proves
        # the closest encloser all at once.
        entry = next(
            e
            for e in proof.evidence
            if e.name == dns.name.from_text("ent.sub.example.")
        )
        self.assertEqual(
            set(entry.roles),
            {
                dns.dnssec.NSECRole.CLOSEST_ENCLOSER,
                dns.dnssec.NSECRole.NEXT_CLOSER,
                dns.dnssec.NSECRole.WILDCARD_POSSIBILITY,
            },
        )

    def test_nxdomain_wrap_around(self):
        # The zzz -> example NSEC wraps the ordering at the apex and must
        # cover both zzzz.example and *.example.
        proof = self._validate("zzzz.example.", "A", ["example.", "zzz.example."])
        self.assertTrue(proof.is_nxdomain)
        zzz = next(
            e for e in proof.evidence if e.name == dns.name.from_text("zzz.example.")
        )
        self.assertEqual(zzz.roles, (dns.dnssec.NSECRole.NEXT_CLOSER,))

    def test_wildcard_nodata(self):
        # *.wild has an A record but no MX; a query for a covered name's MX
        # is a wildcard NODATA.
        proof = self._validate(
            "nomatch.wild.example.",
            "MX",
            ["example.", "mail.example.", "*.wild.example."],
        )
        self.assertTrue(proof.is_nodata)
        wildcard_entry = next(
            e for e in proof.evidence if e.name == dns.name.from_text("*.wild.example.")
        )
        self.assertEqual(
            wildcard_entry.roles,
            (dns.dnssec.NSECRole.WILDCARD_EXPANSION,),
        )
        roles = {r for e in proof.evidence for r in e.roles}
        self.assertIn(dns.dnssec.NSECRole.NEXT_CLOSER, roles)
        self.assertIn(dns.dnssec.NSECRole.CLOSEST_ENCLOSER, roles)

    def test_wildcard_with_queried_type_contradicts(self):
        with self.assertRaises(ValidationFailure):
            self._validate(
                "nomatch.wild.example.",
                "A",
                ["example.", "mail.example.", "*.wild.example."],
            )

    def test_message_entry_point(self):
        qname = dns.name.from_text("nomail.example.")
        query = dns.message.make_query(qname, dns.rdatatype.A)
        response = dns.message.make_response(query)
        response.set_rcode(dns.rcode.NXDOMAIN)
        for name in ("example.", "mail.example."):
            response.authority.append(self._nsec(name))
            response.authority.append(self._nsec_rrsig(name))
        proof = dns.dnssec.validate_nsec_negative_message(
            qname, dns.rdatatype.A, self.keys, response, now=NOW
        )
        self.assertTrue(proof.is_nxdomain)

    def test_relative_inputs_with_origin(self):
        names = ["example.", "mail.example."]
        nsecs, rrsigs = self._materials(names)
        rel_nsecs = [
            (rrset.name.relativize(ORIGIN), rrset.to_rdataset()) for rrset in nsecs
        ]
        rel_rrsigs = [
            (rrset.name.relativize(ORIGIN), rrset.to_rdataset()) for rrset in rrsigs
        ]
        # A genuinely relative query name (no root label).
        relative_qname = dns.name.Name([b"nomail"])
        proof = dns.dnssec.validate_nsec_negative_proof(
            relative_qname,
            dns.rdatatype.A,
            self.keys,
            rel_nsecs,
            rel_rrsigs,
            now=NOW,
            origin=ORIGIN,
        )
        self.assertTrue(proof.is_nxdomain)

    # ------------------------------------------------------------------
    # Incomplete evidence: removing any supporting record breaks the claim
    # ------------------------------------------------------------------

    def test_removing_closest_encloser_is_incomplete(self):
        with self.assertRaises(IncompleteProof):
            self._validate("nomail.example.", "A", ["mail.example."])

    def test_removing_covering_nsec_is_incomplete(self):
        with self.assertRaises(IncompleteProof):
            self._validate("nomail.example.", "A", ["example."])

    def test_removing_wildcard_nsec_downgrades_claim(self):
        # Without the wildcard NSEC the remaining records still prove the
        # name is absent (NXDOMAIN), but they can no longer support a
        # wildcard NODATA conclusion.
        proof = self._validate(
            "nomatch.wild.example.",
            "MX",
            ["example.", "mail.example.", "ns1.example."],
        )
        self.assertTrue(proof.is_nxdomain)
        roles = {r for e in proof.evidence for r in e.roles}
        self.assertNotIn(dns.dnssec.NSECRole.WILDCARD_EXPANSION, roles)

    def test_removing_exact_name_nsec_is_incomplete(self):
        with self.assertRaises(IncompleteProof):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("host.example."),
                dns.rdatatype.TXT,
                self.keys,
                [],
                [],
                now=NOW,
            )

    def test_every_evidence_record_is_necessary(self):
        # A minimal wildcard NODATA proof needs three distinct NSECs.
        # Removing a record that proves name absence must make any negative
        # claim impossible, while removing the wildcard NSEC can only leave
        # an NXDOMAIN, never the original NODATA.
        names = ["example.", "mail.example.", "*.wild.example."]
        proof = self._validate("nomatch.wild.example.", "MX", names)
        necessary = {entry.name for entry in proof.evidence}
        self.assertEqual(necessary, {dns.name.from_text(n) for n in names})

        for removed in ("example.", "mail.example."):
            remaining = [n for n in names if n != removed]
            with self.assertRaises(IncompleteProof):
                self._validate("nomatch.wild.example.", "MX", remaining)

        downgraded = self._validate(
            "nomatch.wild.example.",
            "MX",
            ["example.", "mail.example."],
        )
        self.assertTrue(downgraded.is_nxdomain)
        self.assertNotIn(
            dns.dnssec.NSECRole.WILDCARD_EXPANSION,
            {r for e in downgraded.evidence for r in e.roles},
        )

    # ------------------------------------------------------------------
    # Signature and time validation
    # ------------------------------------------------------------------

    def test_missing_rrsig_fails(self):
        nsecs, _ = self._materials(["example.", "mail.example."])
        with self.assertRaises(IncompleteProof):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("nomail.example."),
                dns.rdatatype.A,
                self.keys,
                nsecs,
                [],
                now=NOW,
            )

    def test_expired_signature_fails(self):
        with self.assertRaises(ValidationFailure):
            self._validate(
                "nomail.example.",
                "A",
                ["example.", "mail.example."],
                now=EXPIRATION + 10,
            )

    def test_not_yet_valid_signature_fails(self):
        with self.assertRaises(ValidationFailure):
            self._validate(
                "nomail.example.",
                "A",
                ["example.", "mail.example."],
                now=INCEPTION - 10,
            )

    def test_corrupted_signature_fails(self):
        nsecs, rrsigs = self._materials(["example.", "mail.example."])
        bad_sig = list(rrsigs[0])[0].replace(signature=b"\x00" * 64)
        rrsigs[0] = dns.rrset.from_rdata(rrsigs[0].name, rrsigs[0].ttl, bad_sig)
        with self.assertRaises(ValidationFailure):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("nomail.example."),
                dns.rdatatype.A,
                self.keys,
                nsecs,
                rrsigs,
                now=NOW,
            )

    def test_untrusted_key_fails(self):
        rogue = ed25519.Ed25519PrivateKey.generate()
        rogue_key = dns.dnssec.make_dnskey(
            rogue.public_key(), dns.dnssec.ED25519, flags=Flag.ZONE
        )
        rogue_keys = {ORIGIN: dns.rrset.from_rdata(ORIGIN, 3600, rogue_key)}
        nsecs, rrsigs = self._materials(["example.", "mail.example."])
        with self.assertRaises(ValidationFailure):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("nomail.example."),
                dns.rdatatype.A,
                rogue_keys,
                nsecs,
                rrsigs,
                now=NOW,
            )

    def test_rrsig_from_unrelated_owner_cannot_authenticate(self):
        # Present the example/mail NSECs but only RRSIGs owned by host;
        # neither NSEC has a signature at its own owner name.
        nsecs, _ = self._materials(["example.", "mail.example."])
        _, rrsigs = self._materials(["host.example."])
        with self.assertRaises((IncompleteProof, ValidationFailure)):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("nomail.example."),
                dns.rdatatype.A,
                self.keys,
                nsecs,
                rrsigs,
                now=NOW,
            )

    def test_rrsig_covering_wrong_type_is_rejected(self):
        nsecs, _ = self._materials(["example.", "mail.example."])
        real = list(self._nsec_rrsig("example."))[0]
        wrong = real.replace(type_covered=dns.rdatatype.A)
        wrong_rrset = dns.rrset.from_rdata(dns.name.from_text("example."), 300, wrong)
        with self.assertRaises(ValidationFailure):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("nomail.example."),
                dns.rdatatype.A,
                self.keys,
                nsecs,
                [wrong_rrset, self._nsec_rrsig("mail.example.")],
                now=NOW,
            )

    # ------------------------------------------------------------------
    # Zone membership and contradictions
    # ------------------------------------------------------------------

    def test_foreign_zone_nsec_cannot_prove(self):
        foreign_nsec = self.other_zone.find_rrset(
            dns.name.from_text("other."), dns.rdatatype.NSEC
        )
        foreign_rrsig = self.other_zone.find_rrset(
            dns.name.from_text("other."),
            dns.rdatatype.RRSIG,
            covers=dns.rdatatype.NSEC,
        )
        with self.assertRaises(ValidationFailure):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("nomail.example."),
                dns.rdatatype.A,
                self.keys,
                [foreign_nsec],
                [foreign_rrsig],
                now=NOW,
            )

    def test_foreign_zone_material_cannot_fill_gap(self):
        # A valid example-zone covering NSEC plus an unrelated foreign NSEC
        # still cannot establish the closest encloser.
        foreign_nsec = self.other_zone.find_rrset(
            dns.name.from_text("other."), dns.rdatatype.NSEC
        )
        foreign_rrsig = self.other_zone.find_rrset(
            dns.name.from_text("other."),
            dns.rdatatype.RRSIG,
            covers=dns.rdatatype.NSEC,
        )
        nsecs, rrsigs = self._materials(["mail.example."])
        with self.assertRaises(IncompleteProof):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("nomail.example."),
                dns.rdatatype.A,
                self.keys,
                [*nsecs, foreign_nsec],
                [*rrsigs, foreign_rrsig],
                now=NOW,
            )

    def test_exact_nsec_asserting_type_contradicts(self):
        with self.assertRaises(ValidationFailure):
            self._validate("host.example.", "A", ["host.example."])

    def test_contradictory_nsec_rdata_at_same_owner(self):
        nsecs, rrsigs = self._materials(["host.example."])
        forged = cast(dns.rdtypes.ANY.NSEC.NSEC, list(nsecs[0])[0]).replace(
            next=dns.name.from_text("zzz.example.")
        )
        nsecs.append(
            dns.rrset.from_rdata(dns.name.from_text("host.example."), 300, forged)
        )
        with self.assertRaises(ValidationFailure):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("host.example."),
                dns.rdatatype.TXT,
                self.keys,
                nsecs,
                rrsigs,
                now=NOW,
            )

    def test_cname_target_must_be_validated(self):
        # host has a CNAME-free NSEC but claims MX; querying MX is NODATA.
        # If the bitmap were to include CNAME, a non-CNAME query must fail
        # and point the caller at the CNAME target instead.
        nsecs, rrsigs = self._materials(["host.example."])
        original = cast(dns.rdtypes.ANY.NSEC.NSEC, list(nsecs[0])[0])
        with_cname = original.replace(
            windows=dns.rdtypes.ANY.NSEC.Bitmap.from_rdtypes(
                [
                    dns.rdatatype.A,
                    dns.rdatatype.MX,
                    dns.rdatatype.CNAME,
                    dns.rdatatype.RRSIG,
                    dns.rdatatype.NSEC,
                ]
            ).windows
        )
        nsecs[0] = dns.rrset.from_rdata(
            dns.name.from_text("host.example."), 300, with_cname
        )
        with self.assertRaises(ValidationFailure):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("host.example."),
                dns.rdatatype.TXT,
                self.keys,
                nsecs,
                rrsigs,
                now=NOW,
            )

    # ------------------------------------------------------------------
    # Additional edge cases
    # ------------------------------------------------------------------

    def test_apex_nodata(self):
        # The apex exists (SOA/NS/DNSKEY) but has no A record.
        proof = self._validate("example.", "A", ["example."])
        self.assertTrue(proof.is_nodata)
        self.assertEqual(proof.closest_encloser, ORIGIN)

    def test_relative_input_without_origin_fails(self):
        relative_nsec = dns.name.Name([b"host"])
        nsecs, rrsigs = self._materials(["host.example."])
        rel_nsecs = [
            (relative_nsec, nsecs[0].to_rdataset()),
        ]
        with self.assertRaises(ValidationFailure):
            dns.dnssec.validate_nsec_negative_proof(
                relative_nsec,
                dns.rdatatype.TXT,
                self.keys,
                rel_nsecs,
                rrsigs,
                now=NOW,
            )

    def test_message_with_nsec3_covering_rrsig_rejected(self):
        qname = dns.name.from_text("host.example.")
        query = dns.message.make_query(qname, dns.rdatatype.A)
        response = dns.message.make_response(query)
        response.authority.append(self._nsec("host.example."))
        nsec3_sig = list(self._nsec_rrsig("host.example."))[0].replace(
            type_covered=dns.rdatatype.NSEC3
        )
        response.authority.append(dns.rrset.from_rdata(qname, 300, nsec3_sig))
        with self.assertRaises(NSEC3Unsupported):
            dns.dnssec.validate_nsec_negative_message(
                qname, dns.rdatatype.A, self.keys, response, now=NOW
            )

    def test_canonical_ordering_not_string_ordering(self):
        # Names differing only in case compare as the same canonical name,
        # and the validator never relies on textual ordering.
        proof = self._validate("NoMail.Example.", "A", ["example.", "mail.example."])
        self.assertTrue(proof.is_nxdomain)

    # ------------------------------------------------------------------
    # NSEC3 is explicitly out of scope
    # ------------------------------------------------------------------

    def test_nsec3_rrset_rejected(self):
        nsec3 = dns.rrset.from_text(
            "host.example.",
            300,
            "IN",
            "NSEC3",
            "1 0 0 - 2G7B44B2Q2J9U3QRM5U8R4A6UQNR0RT6 A RRSIG",
        )
        with self.assertRaises(NSEC3Unsupported):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("host.example."),
                dns.rdatatype.A,
                self.keys,
                [nsec3],
                [],
                now=NOW,
            )

    def test_nsec3_covering_rrsig_rejected(self):
        real = list(self._nsec_rrsig("host.example."))[0]
        nsec3_sig = real.replace(type_covered=dns.rdatatype.NSEC3)
        sig_rrset = dns.rrset.from_rdata(
            dns.name.from_text("host.example."), 300, nsec3_sig
        )
        with self.assertRaises(NSEC3Unsupported):
            dns.dnssec.validate_nsec_negative_proof(
                dns.name.from_text("host.example."),
                dns.rdatatype.A,
                self.keys,
                [self._nsec("host.example.")],
                [sig_rrset],
                now=NOW,
            )

    def test_message_with_nsec3_rejected(self):
        qname = dns.name.from_text("host.example.")
        query = dns.message.make_query(qname, dns.rdatatype.A)
        response = dns.message.make_response(query)
        response.authority.append(
            dns.rrset.from_text(
                "host.example.",
                300,
                "IN",
                "NSEC3",
                "1 0 0 - 2G7B44B2Q2J9U3QRM5U8R4A6UQNR0RT6 A RRSIG",
            )
        )
        with self.assertRaises(NSEC3Unsupported):
            dns.dnssec.validate_nsec_negative_message(
                qname, dns.rdatatype.A, self.keys, response, now=NOW
            )


if __name__ == "__main__":
    unittest.main()
