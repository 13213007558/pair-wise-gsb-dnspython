# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import io
import textwrap
import unittest

import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rdtypes.ANY.ZONEMD
import dns.rrset
import dns.zone
import dns.zonemd
from dns.zonetypes import DigestHashAlgorithm


class ZonemdTestCase(unittest.TestCase):

    zone_text = textwrap.dedent("""
        example.        3600  IN  SOA   ns1.example. admin.example. 2018031900 (
                                        1800 900 604800 86400 )
        example.        3600  IN  NS    ns1.example.
        example.        3600  IN  NS    ns2.example.
        example.        3600  IN  MX    10 mail.example.
        ns1.example.    3600  IN  A     192.0.2.1
        ns2.example.    3600  IN  A     192.0.2.2
        mail.example.   3600  IN  A     192.0.2.3
        www.example.    3600  IN  AAAA  2001:db8::1
    """)

    shuffled_text = textwrap.dedent("""
        www.example.    3600  IN  AAAA  2001:db8::1
        mail.example.   3600  IN  A     192.0.2.3
        ns2.example.    3600  IN  A     192.0.2.2
        ns1.example.    3600  IN  A     192.0.2.1
        example.        3600  IN  MX    10 mail.example.
        example.        3600  IN  NS    ns2.example.
        example.        3600  IN  NS    ns1.example.
        example.        3600  IN  SOA   ns1.example. admin.example. 2018031900 (
                                        1800 900 604800 86400 )
    """)

    uppercase_text = textwrap.dedent("""
        EXAMPLE.        3600  IN  SOA   NS1.EXAMPLE. ADMIN.EXAMPLE. 2018031900 (
                                        1800 900 604800 86400 )
        EXAMPLE.        3600  IN  NS    NS1.EXAMPLE.
        EXAMPLE.        3600  IN  NS    NS2.EXAMPLE.
        EXAMPLE.        3600  IN  MX    10 MAIL.EXAMPLE.
        NS1.EXAMPLE.    3600  IN  A     192.0.2.1
        NS2.EXAMPLE.    3600  IN  A     192.0.2.2
        MAIL.EXAMPLE.   3600  IN  A     192.0.2.3
        WWW.EXAMPLE.    3600  IN  AAAA  2001:db8::1
    """)

    # The number of RRs in zone_text.
    rr_count = 8

    def make_zone(self, text=None, **kwargs):
        if text is None:
            text = self.zone_text
        return dns.zone.from_text(text, origin="example.", **kwargs)

    def make_zonemd(self, zone, serial, scheme, hash_algorithm, digest):
        return dns.rdtypes.ANY.ZONEMD.ZONEMD(
            dns.rdataclass.IN,
            dns.rdatatype.ZONEMD,
            serial,
            scheme,
            hash_algorithm,
            digest,
        )

    def test_compute_sha384(self):
        zone = self.make_zone()
        rrset = dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA384)
        self.assertIsInstance(rrset, dns.rrset.RRset)
        self.assertEqual(rrset.name, zone.origin)
        self.assertEqual(rrset.rdtype, dns.rdatatype.ZONEMD)
        self.assertEqual(rrset.ttl, 3600)
        zonemd = rrset[0]
        self.assertEqual(zonemd.serial, 2018031900)
        self.assertEqual(zonemd.scheme, 1)
        self.assertEqual(zonemd.hash_algorithm, DigestHashAlgorithm.SHA384)
        self.assertEqual(len(zonemd.digest), 48)
        dns.zonemd.verify_zonemd(zone, rrset)
        # Computing must not modify the input zone.
        self.assertIsNone(zone.get_rdataset(zone.origin, "ZONEMD"))

    def test_compute_sha512(self):
        zone = self.make_zone()
        rrset = dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA512)
        zonemd = rrset[0]
        self.assertEqual(zonemd.hash_algorithm, DigestHashAlgorithm.SHA512)
        self.assertEqual(len(zonemd.digest), 64)
        dns.zonemd.verify_zonemd(zone, rrset)
        self.assertIsNone(zone.get_rdataset(zone.origin, "ZONEMD"))

    def test_attach(self):
        zone = self.make_zone()
        rrset = dns.zonemd.compute_zonemd(zone, attach=True)
        self.assertIsNotNone(zone.get_rdataset(zone.origin, "ZONEMD"))
        dns.zonemd.verify_zonemd(zone)
        # The attached ZONEMD RRset is excluded from the digest, so
        # recomputation is idempotent.
        rrset2 = dns.zonemd.compute_zonemd(zone)
        self.assertEqual(rrset[0], rrset2[0])

    def test_explicit_serial_and_ttl(self):
        zone = self.make_zone()
        rrset = dns.zonemd.compute_zonemd(zone, serial=42, ttl=300)
        self.assertEqual(rrset[0].serial, 42)
        self.assertEqual(rrset.ttl, 300)

    def test_write_and_read_back(self):
        zone = self.make_zone()
        # Attach digests for both algorithms as a single ZONEMD RRset.
        dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA384, attach=True)
        rrset512 = dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA512)
        attached = zone.get_rdataset(zone.origin, "ZONEMD")
        attached.add(rrset512[0], rrset512.ttl)
        f = io.StringIO()
        zone.to_file(f)
        zone2 = dns.zone.from_text(f.getvalue(), origin="example.")
        dns.zonemd.verify_zonemd(zone2)
        zonemd = zone2.get_rdataset(zone2.origin, "ZONEMD")
        self.assertEqual(len(zonemd), 2)
        for rr in zonemd:
            dns.zonemd.verify_zonemd(zone2, rr)

    def test_bad_digest(self):
        zone = self.make_zone()
        good = dns.zonemd.compute_zonemd(zone)[0]
        bad_digest = bytes([good.digest[0] ^ 1]) + good.digest[1:]
        bad = self.make_zonemd(
            zone, good.serial, good.scheme, good.hash_algorithm, bad_digest
        )
        with self.assertRaises(dns.zone.DigestVerificationFailure):
            dns.zonemd.verify_zonemd(zone, bad)

    def test_multiple_zonemd(self):
        zone = self.make_zone()
        good384 = dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA384)[0]
        good512 = dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA512)[0]
        bad512 = self.make_zonemd(
            zone,
            good512.serial,
            1,
            2,
            bytes([good512.digest[0] ^ 1]) + good512.digest[1:],
        )
        # Verification succeeds if at least one record verifies, regardless
        # of order.
        rrset = dns.rrset.RRset(zone.origin, dns.rdataclass.IN, dns.rdatatype.ZONEMD)
        rrset.add(bad512, 3600)
        rrset.add(good384, 3600)
        dns.zonemd.verify_zonemd(zone, rrset)
        rrset2 = dns.rrset.RRset(zone.origin, dns.rdataclass.IN, dns.rdatatype.ZONEMD)
        rrset2.add(good384, 3600)
        rrset2.add(good512, 3600)
        dns.zonemd.verify_zonemd(zone, rrset2)
        # A single bad record on its own fails.
        with self.assertRaises(dns.zone.DigestVerificationFailure):
            dns.zonemd.verify_zonemd(zone, bad512)

    def test_multiple_zonemd_with_unsupported(self):
        # An unsupported record does not prevent another record from
        # verifying.
        zone = self.make_zone()
        good = dns.zonemd.compute_zonemd(zone)[0]
        unsupported = self.make_zonemd(zone, good.serial, 1, 240, b"\xab\xcd")
        rrset = dns.rrset.RRset(zone.origin, dns.rdataclass.IN, dns.rdatatype.ZONEMD)
        rrset.add(unsupported, 3600)
        rrset.add(good, 3600)
        dns.zonemd.verify_zonemd(zone, rrset)

    def test_multiple_zonemd_first_failure_wins(self):
        zone = self.make_zone()
        good = dns.zonemd.compute_zonemd(zone)[0]
        wrong_serial = self.make_zonemd(zone, good.serial + 1, 1, 1, good.digest)
        bad_digest = self.make_zonemd(
            zone, good.serial, 1, 1, bytes([good.digest[0] ^ 1]) + good.digest[1:]
        )
        rrset = dns.rrset.RRset(zone.origin, dns.rdataclass.IN, dns.rdatatype.ZONEMD)
        rrset.add(wrong_serial, 3600)
        rrset.add(bad_digest, 3600)
        with self.assertRaises(dns.zonemd.DigestSerialMismatch):
            dns.zonemd.verify_zonemd(zone, rrset)
        rrset2 = dns.rrset.RRset(zone.origin, dns.rdataclass.IN, dns.rdatatype.ZONEMD)
        rrset2.add(bad_digest, 3600)
        rrset2.add(wrong_serial, 3600)
        with self.assertRaises(dns.zone.DigestVerificationFailure):
            dns.zonemd.verify_zonemd(zone, rrset2)

    def test_empty_zonemd_rrset(self):
        zone = self.make_zone()
        rrset = dns.rrset.RRset(zone.origin, dns.rdataclass.IN, dns.rdatatype.ZONEMD)
        with self.assertRaises(dns.zone.DigestVerificationFailure):
            dns.zonemd.verify_zonemd(zone, rrset)

    def test_serial_mismatch(self):
        zone = self.make_zone()
        # The digest is still correct; only the serial number is wrong.
        good = dns.zonemd.compute_zonemd(zone)[0]
        wrong_serial = self.make_zonemd(
            zone, good.serial + 1, good.scheme, good.hash_algorithm, good.digest
        )
        with self.assertRaises(dns.zonemd.DigestSerialMismatch):
            dns.zonemd.verify_zonemd(zone, wrong_serial)
        # Bumping the SOA serial invalidates a previously computed digest.
        dns.zonemd.compute_zonemd(zone, attach=True)
        zone.replace_rdataset(
            zone.origin,
            dns.rdataset.from_text(
                "IN",
                "SOA",
                3600,
                "ns1.example. admin.example. 2018031901 1800 900 604800 86400",
            ),
        )
        with self.assertRaises(dns.zonemd.DigestSerialMismatch):
            dns.zonemd.verify_zonemd(zone)

    def test_unsupported_scheme(self):
        zone = self.make_zone()
        with self.assertRaises(dns.zone.UnsupportedDigestScheme):
            dns.zonemd.compute_zonemd(zone, scheme=2)
        zonemd = self.make_zonemd(zone, 2018031900, 2, 1, b"\xab" * 48)
        with self.assertRaises(dns.zone.UnsupportedDigestScheme):
            dns.zonemd.verify_zonemd(zone, zonemd)

    def test_unsupported_hash_algorithm(self):
        zone = self.make_zone()
        with self.assertRaises(dns.zone.UnsupportedDigestHashAlgorithm):
            dns.zonemd.compute_zonemd(zone, hash_algorithm=5)
        zonemd = self.make_zonemd(zone, 2018031900, 1, 240, b"\xab\xcd")
        with self.assertRaises(dns.zone.UnsupportedDigestHashAlgorithm):
            dns.zonemd.verify_zonemd(zone, zonemd)

    def test_no_origin(self):
        zone = dns.zone.Zone(None)
        with self.assertRaises(dns.zone.UnknownOrigin):
            dns.zonemd.compute_zonemd(zone)
        with self.assertRaises(dns.zone.UnknownOrigin):
            dns.zonemd.verify_zonemd(zone)

    def test_no_soa(self):
        text = textwrap.dedent("""
            example.      3600  IN  NS    ns1.example.
            ns1.example.  3600  IN  A     192.0.2.1
        """)
        zone = self.make_zone(text, check_origin=False)
        with self.assertRaises(dns.zone.NoSOA):
            dns.zonemd.compute_zonemd(zone)
        # An explicit serial number makes the SOA unnecessary.
        rrset = dns.zonemd.compute_zonemd(zone, serial=42)
        self.assertEqual(rrset[0].serial, 42)

    def test_no_digest(self):
        zone = self.make_zone()
        with self.assertRaises(dns.zone.NoDigest):
            dns.zonemd.verify_zonemd(zone)

    def test_empty_non_terminal(self):
        zone = self.make_zone()
        before = dns.zonemd.compute_zonemd(zone)
        # A blank node (empty non-terminal) has no rdatasets and does not
        # participate in the digest.
        zone.find_node("empty", create=True)
        after = dns.zonemd.compute_zonemd(zone)
        self.assertEqual(before, after)

    def test_only_blank_nodes(self):
        # A zone with only blank nodes has no SOA, so a serial number
        # cannot be determined.
        zone = dns.zone.Zone("example.")
        zone.find_node("blank", create=True)
        with self.assertRaises(dns.zone.NoSOA):
            dns.zonemd.compute_zonemd(zone)

    def test_insertion_order_is_canonical(self):
        zone1 = self.make_zone()
        zone2 = self.make_zone(self.shuffled_text)
        self.assertEqual(
            dns.zonemd.compute_zonemd(zone1), dns.zonemd.compute_zonemd(zone2)
        )

    def test_case_is_canonical(self):
        zone1 = self.make_zone()
        zone2 = self.make_zone(self.uppercase_text)
        self.assertEqual(
            dns.zonemd.compute_zonemd(zone1), dns.zonemd.compute_zonemd(zone2)
        )

    def test_relativization_is_canonical(self):
        zone1 = self.make_zone()
        zone2 = self.make_zone(relativize=False)
        self.assertEqual(
            dns.zonemd.compute_zonemd(zone1), dns.zonemd.compute_zonemd(zone2)
        )

    def test_ttl_representation_is_canonical(self):
        zone1 = self.make_zone()
        zone2 = self.make_zone(self.zone_text.replace("3600", "1H"))
        self.assertEqual(
            dns.zonemd.compute_zonemd(zone1), dns.zonemd.compute_zonemd(zone2)
        )

    def test_ttl_change_changes_digest(self):
        # The TTL is part of the digested data (RFC 8976 section 4.1).
        zone1 = self.make_zone()
        zone2 = self.make_zone(self.zone_text.replace("3600", "7200"))
        self.assertNotEqual(
            dns.zonemd.compute_zonemd(zone1), dns.zonemd.compute_zonemd(zone2)
        )

    def test_rdata_change_fails_verification(self):
        zone1 = self.make_zone()
        rrset = dns.zonemd.compute_zonemd(zone1)
        zone2 = self.make_zone(self.zone_text.replace("192.0.2.1", "192.0.2.9"))
        self.assertNotEqual(
            dns.zonemd.compute_zonemd(zone1), dns.zonemd.compute_zonemd(zone2)
        )
        with self.assertRaises(dns.zone.DigestVerificationFailure):
            dns.zonemd.verify_zonemd(zone2, rrset)

    def test_budget(self):
        zone = self.make_zone()
        dns.zonemd.compute_zonemd(zone, budget=self.rr_count)
        with self.assertRaises(dns.zonemd.DigestBudgetExceeded):
            dns.zonemd.compute_zonemd(zone, budget=self.rr_count - 1)
        with self.assertRaises(dns.zonemd.DigestBudgetExceeded):
            dns.zonemd.compute_zonemd(zone, budget=0)
        rrset = dns.zonemd.compute_zonemd(zone)
        dns.zonemd.verify_zonemd(zone, rrset, budget=self.rr_count)
        with self.assertRaises(dns.zonemd.DigestBudgetExceeded):
            dns.zonemd.verify_zonemd(zone, rrset, budget=self.rr_count - 1)

    def test_large_zone(self):
        lines = [self.zone_text]
        for i in range(2000):
            lines.append(f"host{i}.example. 300 IN A 10.0.{i // 256}.{i % 256}\n")
        zone = self.make_zone("".join(lines))
        rrset = dns.zonemd.compute_zonemd(zone)
        dns.zonemd.verify_zonemd(zone, rrset)
        with self.assertRaises(dns.zonemd.DigestBudgetExceeded):
            dns.zonemd.compute_zonemd(zone, budget=self.rr_count + 2000 - 1)


if __name__ == "__main__":
    unittest.main()
