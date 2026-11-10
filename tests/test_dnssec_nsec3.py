# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for RFC 5155 NSEC3 zone signing in dns.dnssec.sign_zone."""

import base64
import hashlib
import unittest

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.zone
from dns.rdtypes.ANY.NSEC3PARAM import NSEC3PARAM
from dns.rdtypes.dnskeybase import Flag

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:  # pragma: no cover
    ed25519 = None

# A small zone exercising every RFC 5155 name class:
#   - the zone apex
#   - a regular name (ns1, host)
#   - an empty non-terminal chain (deep.ent / ent above a.deep.ent)
#   - a wildcard (*.wild) and its (ENT) parent (wild)
#   - a signed delegation, i.e. an NS name with a DS RRset
#   - an unsigned delegation, i.e. an NS name without DS, with a child
#     living below it that must remain outside the signed material
test_zone_text = """
example. 3600 IN SOA foo.example. bar.example. 1 2 3 4 5
example. 3600 IN NS ns1.example.
ns1.example. 3600 IN A 10.0.0.1
host.example. 3600 IN A 10.0.0.9
a.deep.ent.example. 3600 IN TXT foo
*.wild.example. 3600 IN A 10.0.0.10
signed-deleg.example. 3600 IN NS nsx.example.
signed-deleg.example. 3600 IN DS 12345 13 2 0100D208742A23024DF3C8827DFF3EB3E25126E9B72850E99D6055E18913CB2F
unsigned-deleg.example. 3600 IN NS nsy.example.
child.unsigned-deleg.example. 3600 IN A 10.0.0.20
"""

SALT = bytes.fromhex("aabbccdd")
ITERATIONS = 5

# Every name that must be hashed into the chain when Opt-Out is off.
secure_names_no_optout = [
    "example.",
    "ns1.example.",
    "host.example.",
    "a.deep.ent.example.",
    "deep.ent.example.",
    "ent.example.",
    "*.wild.example.",
    "wild.example.",
    "signed-deleg.example.",
    "unsigned-deleg.example.",
]
# Opt-Out removes exactly the unsigned delegation point.
secure_names_optout = [
    n for n in secure_names_no_optout if n != "unsigned-deleg.example."
]


def _b32_decode(value):
    if isinstance(value, bytes):
        value = value.decode()
    return base64.b32hexdecode(value + "=" * (-len(value) % 8))


def _independent_nsec3_hash(domain, salt, iterations):
    """A from-scratch RFC 5155 section 5 implementation, deliberately not
    calling dns.dnssec.nsec3_hash so the test independently recomputes."""
    if not isinstance(domain, dns.name.Name):
        domain = dns.name.from_text(domain)
    digest = hashlib.sha1(domain.canonicalize().to_wire() + salt).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt).digest()
    return digest


def _bitmap_types(nsec3_rdata):
    types = set()
    for window, bitmap in nsec3_rdata.windows:
        for octet_index, octet in enumerate(bitmap):
            for bit in range(8):
                if octet & (0x80 >> bit):
                    types.add(window * 256 + octet_index * 8 + bit)
    return types


@unittest.skipUnless(dns.dnssec._have_pyca, "Python Cryptography cannot be imported")
class NSEC3SignZoneTestCase(unittest.TestCase):
    def setUp(self):
        self.ksk_private = ed25519.Ed25519PrivateKey.generate()
        self.ksk = dns.dnssec.make_dnskey(
            self.ksk_private.public_key(),
            dns.dnssec.Algorithm.ED25519,
            flags=Flag.ZONE | Flag.SEP,
        )
        self.zsk_private = ed25519.Ed25519PrivateKey.generate()
        self.zsk = dns.dnssec.make_dnskey(
            self.zsk_private.public_key(),
            dns.dnssec.Algorithm.ED25519,
            flags=Flag.ZONE,
        )
        self.keys = [
            (self.ksk_private, self.ksk),
            (self.zsk_private, self.zsk),
        ]
        self.param = NSEC3PARAM(
            dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, 1, 0, ITERATIONS, SALT
        )

    def _sign(self, optout=None, zone_text=test_zone_text, param=None, **kwargs):
        zone = dns.zone.from_text(zone_text, "example.")
        param = param or self.param
        with zone.writer() as txn:
            dns.dnssec.sign_zone(
                zone,
                txn=txn,
                keys=self.keys,
                lifetime=3600,
                nsec3=param,
                nsec3_optout=optout,
                **kwargs,
            )
        return zone

    def _nsec3_by_hash(self, zone):
        by_hash = {}
        for name, rdataset in zone.iterate_rdatasets("NSEC3"):
            label = name.relativize(zone.origin).labels[0]
            by_hash[_b32_decode(label)] = rdataset[0]
        return by_hash

    def _assert_chain_matches_names(self, zone, expected_owner_names):
        by_hash = self._nsec3_by_hash(zone)
        expected_hashes = sorted(
            _independent_nsec3_hash(dns.name.from_text(n), SALT, ITERATIONS)
            for n in expected_owner_names
        )
        actual_hashes = sorted(by_hash)
        # No duplicate owner names: each distinct hash appears exactly once.
        self.assertEqual(len(actual_hashes), len(expected_hashes))
        self.assertEqual(actual_hashes, expected_hashes)

        # Walk the next pointers from the smallest hash; every owner must be
        # visited exactly once and the final edge wraps to the first.
        first = actual_hashes[0]
        current = first
        visited = []
        for _ in range(len(actual_hashes)):
            visited.append(current)
            current = by_hash[current].next
        self.assertEqual(current, first, "chain does not close (wrap edge)")
        self.assertEqual(sorted(visited), actual_hashes)
        return by_hash

    def _validate_all_rrsigs(self, zone):
        keys = {zone.origin: zone.find_rdataset(zone.origin, "DNSKEY")}
        count = 0
        for name, rdataset in zone.iterate_rdatasets():
            if rdataset.rdtype != dns.rdatatype.RRSIG:
                continue
            covered = zone.find_rdataset(name, rdataset.covers)
            dns.dnssec.validate((name, covered), (name, rdataset), keys, zone.origin)
            count += 1
        self.assertGreater(count, 0)
        return count

    def test_nsec3_chain_without_optout(self):
        zone = self._sign(optout=False)
        by_hash = self._assert_chain_matches_names(zone, secure_names_no_optout)
        # Every NSEC3 rdata carries the parameters and no Opt-Out flag.
        for rdata in by_hash.values():
            self.assertEqual(rdata.algorithm, 1)
            self.assertEqual(rdata.iterations, ITERATIONS)
            self.assertEqual(rdata.salt, SALT)
            self.assertEqual(rdata.flags, 0)
        # The apex NSEC3PARAM exists, is signed, and has a zero flags field.
        param = zone.find_rdataset(zone.origin, "NSEC3PARAM")[0]
        self.assertEqual((param.algorithm, param.flags), (1, 0))
        self.assertEqual((param.iterations, param.salt), (ITERATIONS, SALT))
        self.assertIsNotNone(
            zone.find_rdataset(zone.origin, "RRSIG", covers=dns.rdatatype.NSEC3PARAM)
        )
        self._validate_all_rrsigs(zone)

    def test_nsec3_chain_with_optout_omits_unsigned_delegation(self):
        zone = self._sign(optout=True)
        by_hash = self._assert_chain_matches_names(zone, secure_names_optout)
        for rdata in by_hash.values():
            self.assertEqual(rdata.flags, 1)  # Opt-Out set on every NSEC3
        # The unsigned delegation has no NSEC3 of its own.
        unsigned_hash = _independent_nsec3_hash(
            dns.name.from_text("unsigned-deleg.example."), SALT, ITERATIONS
        )
        self.assertNotIn(unsigned_hash, by_hash)
        # The signed delegation is still present even with Opt-Out on.
        signed_hash = _independent_nsec3_hash(
            dns.name.from_text("signed-deleg.example."), SALT, ITERATIONS
        )
        self.assertIn(signed_hash, by_hash)
        # NSEC3PARAM flags remain zero regardless of Opt-Out.
        self.assertEqual(zone.find_rdataset(zone.origin, "NSEC3PARAM")[0].flags, 0)
        self._validate_all_rrsigs(zone)

    def test_optout_flag_precedence(self):
        # The nsec3 parameter's flags drive Opt-Out unless overridden.
        param_optout = NSEC3PARAM(
            dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, 1, 1, ITERATIONS, SALT
        )
        zone = self._sign(optout=None, param=param_optout)
        self.assertEqual({r.flags for r in self._nsec3_by_hash(zone).values()}, {1})
        # Explicit keyword overrides a zero parameter flag.
        zone = self._sign(optout=True, param=self.param)
        self.assertEqual({r.flags for r in self._nsec3_by_hash(zone).values()}, {1})
        # Explicit keyword overrides a set parameter flag.
        zone = self._sign(optout=False, param=param_optout)
        self.assertEqual({r.flags for r in self._nsec3_by_hash(zone).values()}, {0})

    def test_delegation_bitmaps(self):
        zone = self._sign(optout=False)
        by_hash = self._nsec3_by_hash(zone)

        signed = by_hash[
            _independent_nsec3_hash(
                dns.name.from_text("signed-deleg.example."), SALT, ITERATIONS
            )
        ]
        signed_types = _bitmap_types(signed)
        # RFC 5155 7.2.3: DS, NS and RRSIG (the NSEC3 is itself signed).
        self.assertIn(dns.rdatatype.NS, signed_types)
        self.assertIn(dns.rdatatype.DS, signed_types)
        self.assertIn(dns.rdatatype.RRSIG, signed_types)

        unsigned = by_hash[
            _independent_nsec3_hash(
                dns.name.from_text("unsigned-deleg.example."), SALT, ITERATIONS
            )
        ]
        unsigned_types = _bitmap_types(unsigned)
        # RFC 5155 7.2.4: NS and RRSIG (its NSEC3 is signed) but no DS bit.
        self.assertIn(dns.rdatatype.NS, unsigned_types)
        self.assertIn(dns.rdatatype.RRSIG, unsigned_types)
        self.assertNotIn(dns.rdatatype.DS, unsigned_types)

    def test_optout_delegation_bitmap_has_no_rrsig_bit(self):
        zone = self._sign(optout=True)
        by_hash = self._nsec3_by_hash(zone)
        signed = by_hash[
            _independent_nsec3_hash(
                dns.name.from_text("signed-deleg.example."), SALT, ITERATIONS
            )
        ]
        types = _bitmap_types(signed)
        # Under Opt-Out the signed delegation keeps NS+DS but its NSEC3 RR
        # is not signed, so the RRSIG bit must not be asserted.
        self.assertIn(dns.rdatatype.NS, types)
        self.assertIn(dns.rdatatype.DS, types)
        self.assertNotIn(dns.rdatatype.RRSIG, types)

    def test_ent_and_wildcard_bitmaps(self):
        zone = self._sign(optout=False)
        by_hash = self._nsec3_by_hash(zone)

        ent = by_hash[
            _independent_nsec3_hash(
                dns.name.from_text("ent.example."), SALT, ITERATIONS
            )
        ]
        self.assertEqual(
            _bitmap_types(ent),
            {dns.rdatatype.NSEC3, dns.rdatatype.RRSIG},
        )
        wildcard = by_hash[
            _independent_nsec3_hash(
                dns.name.from_text("*.wild.example."), SALT, ITERATIONS
            )
        ]
        self.assertEqual(
            _bitmap_types(wildcard),
            {
                dns.rdatatype.A,
                dns.rdatatype.NSEC3,
                dns.rdatatype.RRSIG,
            },
        )

    def test_apex_bitmap(self):
        zone = self._sign(optout=False)
        by_hash = self._nsec3_by_hash(zone)
        apex = by_hash[
            _independent_nsec3_hash(dns.name.from_text("example."), SALT, ITERATIONS)
        ]
        self.assertEqual(
            _bitmap_types(apex),
            {
                dns.rdatatype.SOA,
                dns.rdatatype.NS,
                dns.rdatatype.DNSKEY,
                dns.rdatatype.NSEC3,
                dns.rdatatype.RRSIG,
            },
        )

    def test_child_below_unsigned_delegation_is_not_signed(self):
        zone = self._sign(optout=False)
        child = zone.get_node(dns.name.from_text("child.unsigned-deleg", zone.origin))
        self.assertTrue(all(rd.rdtype != dns.rdatatype.RRSIG for rd in child.rdatasets))

    def test_resign_does_not_accumulate_chain(self):
        zone = self._sign(optout=False)
        first_owners = sorted(str(name) for name, _ in zone.iterate_rdatasets("NSEC3"))
        first_sig_count = sum(
            1 for _, rd in zone.iterate_rdatasets() if rd.rdtype == dns.rdatatype.RRSIG
        )
        # Re-sign with the same parameters.
        with zone.writer() as txn:
            dns.dnssec.sign_zone(
                zone,
                txn=txn,
                keys=self.keys,
                lifetime=3600,
                nsec3=self.param,
                nsec3_optout=False,
            )
        second_owners = sorted(str(name) for name, _ in zone.iterate_rdatasets("NSEC3"))
        second_sig_count = sum(
            1 for _, rd in zone.iterate_rdatasets() if rd.rdtype == dns.rdatatype.RRSIG
        )
        self.assertEqual(first_owners, second_owners)
        self.assertEqual(first_sig_count, second_sig_count)

        # Re-sign with a different salt replaces the whole chain; no old
        # NSEC3 rdata or duplicate NSEC3 RRSIGs survive.
        new_param = NSEC3PARAM(
            dns.rdataclass.IN,
            dns.rdatatype.NSEC3PARAM,
            1,
            0,
            ITERATIONS,
            bytes.fromhex("bb"),
        )
        with zone.writer() as txn:
            dns.dnssec.sign_zone(
                zone,
                txn=txn,
                keys=self.keys,
                lifetime=3600,
                nsec3=new_param,
            )
        for _, rdataset in zone.iterate_rdatasets("NSEC3"):
            self.assertEqual(rdataset[0].salt, bytes.fromhex("bb"))
        per_owner = {}
        for name, rdataset in zone.iterate_rdatasets():
            if (
                rdataset.rdtype == dns.rdatatype.RRSIG
                and rdataset.covers == dns.rdatatype.NSEC3
            ):
                per_owner[name] = per_owner.get(name, 0) + 1
        self.assertTrue(all(count == 1 for count in per_owner.values()))

    def test_failure_leaves_no_partial_chain(self):
        zone = dns.zone.from_text(test_zone_text, "example.")
        before = zone.to_text()

        class _Boom(Exception):
            pass

        def failing_signer(txn, rrset):
            if rrset.rdtype == dns.rdatatype.NSEC3:
                raise _Boom()

        with self.assertRaises(_Boom):
            with zone.writer() as txn:
                dns.dnssec.sign_zone(
                    zone,
                    txn=txn,
                    keys=self.keys,
                    lifetime=3600,
                    nsec3=self.param,
                    rrset_signer=failing_signer,
                )
        # The transaction rolled back: nothing changed at all.
        self.assertEqual(zone.to_text(), before)
        self.assertFalse(
            any(rd.rdtype == dns.rdatatype.NSEC3 for _, rd in zone.iterate_rdatasets())
        )

    def test_apex_only_zone_self_loops(self):
        zone_text = (
            "@ 300 IN SOA ns.other. hostmaster.other. 1 2 3 4 5\n"
            "@ 300 IN NS ns.other.\n"
            "@ 300 IN A 10.0.0.1\n"
        )
        zone = self._sign(zone_text=zone_text)
        nsec3 = list(zone.iterate_rdatasets("NSEC3"))
        self.assertEqual(len(nsec3), 1)
        name, rdataset = nsec3[0]
        owner_hash = _b32_decode(name.relativize(zone.origin).labels[0])
        # A one-entry chain points back at its own hash.
        self.assertEqual(rdataset[0].next, owner_hash)

    def test_invalid_parameters_rejected(self):
        zone = dns.zone.from_text(test_zone_text, "example.")
        bad_algorithm = NSEC3PARAM(
            dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, 2, 0, 0, b""
        )
        with self.assertRaises(ValueError):
            with zone.writer() as txn:
                dns.dnssec.sign_zone(zone, txn=txn, keys=self.keys, nsec3=bad_algorithm)
        bad_flags = NSEC3PARAM(
            dns.rdataclass.IN, dns.rdatatype.NSEC3PARAM, 1, 2, 0, b""
        )
        with self.assertRaises(ValueError):
            with zone.writer() as txn:
                dns.dnssec.sign_zone(zone, txn=txn, keys=self.keys, nsec3=bad_flags)

    def test_nsec_path_remains_default(self):
        zone = dns.zone.from_text(test_zone_text, "example.")
        with zone.writer() as txn:
            dns.dnssec.sign_zone(zone, txn=txn, keys=self.keys, lifetime=3600)
        self.assertTrue(
            any(rd.rdtype == dns.rdatatype.NSEC for _, rd in zone.iterate_rdatasets())
        )
        self.assertFalse(
            any(rd.rdtype == dns.rdatatype.NSEC3 for _, rd in zone.iterate_rdatasets())
        )

    def test_null_rrset_signer_still_generates_chain(self):
        def null_signer(txn, rrset):
            pass

        zone = self._sign(optout=False, rrset_signer=null_signer)
        # Chain material exists even though nothing was signed.
        owners = list(zone.iterate_rdatasets("NSEC3"))
        self.assertEqual(len(owners), len(secure_names_no_optout))
        self.assertIsNotNone(zone.find_rdataset(zone.origin, "NSEC3PARAM"))

    def test_hash_collision_merges_owners_and_bitmaps(self):
        # Force two distinct names onto one digest; they must share a single
        # NSEC3 RR whose bitmap is the union of their types.
        zone_text = (
            "@ 3600 IN SOA ns.other. hostmaster.other. 1 2 3 4 5\n"
            "@ 3600 IN NS ns.other.\n"
            "host.example. 3600 IN A 10.0.0.9\n"
            "txt.example. 3600 IN TXT hello\n"
        )
        real_hash = dns.dnssec._nsec3_hash_bytes
        collision_digest = b"\x11" * 20

        def forced_hash(domain, salt, iterations, algorithm):
            if str(domain) in ("host.example.", "txt.example."):
                return collision_digest
            return real_hash(domain, salt, iterations, algorithm)

        dns.dnssec._nsec3_hash_bytes = forced_hash
        try:
            zone = self._sign(zone_text=zone_text)
        finally:
            dns.dnssec._nsec3_hash_bytes = real_hash

        nsec3 = list(zone.iterate_rdatasets("NSEC3"))
        # Apex plus the single merged collision record.
        self.assertEqual(len(nsec3), 2)
        collision_record = [
            rdataset[0]
            for name, rdataset in nsec3
            if name.relativize(zone.origin).labels[0]
            == base64.b32hexencode(collision_digest).rstrip(b"=")
        ]
        self.assertEqual(len(collision_record), 1)
        types = _bitmap_types(collision_record[0])
        self.assertEqual(
            types,
            {
                dns.rdatatype.A,
                dns.rdatatype.TXT,
                dns.rdatatype.NSEC3,
                dns.rdatatype.RRSIG,
            },
        )
        # The chain is still a closed loop over the merged owners.
        by_hash = self._nsec3_by_hash(zone)
        ordered = sorted(by_hash)
        for index, digest in enumerate(ordered):
            self.assertEqual(by_hash[digest].next, ordered[(index + 1) % len(ordered)])

    def test_relativized_zone(self):
        # Signing must work when zone names are stored relative.
        zone = dns.zone.from_text(test_zone_text, "example.", relativize=True)
        with zone.writer() as txn:
            dns.dnssec.sign_zone(
                zone, txn=txn, keys=self.keys, lifetime=3600, nsec3=self.param
            )
        self._assert_chain_matches_names(zone, secure_names_no_optout)
        self._validate_all_rrsigs(zone)


if __name__ == "__main__":
    unittest.main()
