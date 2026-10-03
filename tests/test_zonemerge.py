# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for dns.zonemerge."""

import unittest

import dns.name
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.zone
import dns.zonemerge


BASE = """$TTL 3600
$ORIGIN example.
@ IN SOA ns1 hostmaster 1 7200 3600 1209600 3600
@ IN NS ns1
@ IN NS ns2
ns1 IN A 10.0.0.1
ns2 IN A 10.0.0.2
www IN A 1.1.1.1
mx  IN MX 10 mail
"""


def zone(text=BASE, relativize=True, serial=None):
    if serial is not None:
        # Convenience: replace the serial while keeping the rest fixed.
        lines = []
        for line in text.splitlines():
            if "SOA" in line:
                fields = line.split()
                fields[5] = str(serial)
                line = " ".join(fields)
            lines.append(line)
        text = "\n".join(lines) + "\n"
    return dns.zone.from_text(
        text,
        origin="example.",
        relativize=relativize,
        check_origin=False,
    )


def modify(*, text=BASE, remove=(), add=(), serial=1):
    """Build a zone from BASE, dropping records at selected units and
    appending replacement/additional record lines.
    """

    removed = set(remove)
    lines = []
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) < 3 or fields[0].startswith("$"):
            lines.append(line)
            continue
        owner = fields[0].lower()
        rtype = fields[2].upper()
        if (owner, rtype) in removed:
            continue
        lines.append(line)
    if add:
        lines.extend(add)
    text = "\n".join(lines) + "\n"
    return zone(text, serial=serial)


def without(zone_text, owner, rtype):
    z = zone(zone_text)
    z.delete_rdataset(owner, rtype)
    return z


class MergeTestCase(unittest.TestCase):
    def assertConflicts(self, result, reasons):
        self.assertIsNone(result.merged)
        self.assertEqual(
            [conflict.reason for conflict in result.conflicts],
            list(reasons),
        )

    def test_different_hosts_merge(self):
        # The caller example: each side adds a different host, the merge
        # takes both.
        ours = modify(add=("host-a IN A 1.2.3.4",))
        theirs = modify(add=("host-b IN A 4.3.2.1",))
        merged = dns.zonemerge.merge(zone(), ours, theirs)
        self.assertEqual(merged.get_rdataset("host-a", "A")[0].address, "1.2.3.4")
        self.assertEqual(merged.get_rdataset("host-b", "A")[0].address, "4.3.2.1")
        # Unchanged records survive.
        self.assertEqual(merged.get_rdataset("ns1", "A")[0].address, "10.0.0.1")

    def test_different_records_of_same_host_merge(self):
        # Distinct types at a newly shared owner are independent units.
        ours = modify(add=("host IN A 1.2.3.4",))
        theirs = modify(add=("host IN AAAA 2001:db8::1",))
        merged = dns.zonemerge.merge(zone(), ours, theirs)
        self.assertIsNotNone(merged.get_rdataset("host", "A"))
        self.assertIsNotNone(merged.get_rdataset("host", "AAAA"))

    def test_only_one_side_changes(self):
        ours = modify(remove={("www", "A")}, add=("www IN A 2.2.2.2",))
        merged = dns.zonemerge.merge(zone(), ours, zone())
        self.assertEqual(merged.get_rdataset("www", "A")[0].address, "2.2.2.2")

    def test_both_same_change(self):
        changed = modify(remove={("www", "A")}, add=("www IN A 2.2.2.2",))
        merged = dns.zonemerge.merge(zone(), changed, changed)
        self.assertEqual(merged.get_rdataset("www", "A")[0].address, "2.2.2.2")

    def test_ttl_conflict(self):
        # The caller example: both sides change the TTL of the same
        # RRset differently; no automatic merge.
        ours = modify(remove={("www", "A")}, add=("www 600 IN A 1.1.1.1",))
        theirs = modify(remove={("www", "A")}, add=("www 900 IN A 1.1.1.1",))
        result = dns.zonemerge.try_merge(zone(), ours, theirs)
        self.assertConflicts(result, [dns.zonemerge.ConflictReason.CONFLICTING_CHANGES])
        c = result.conflicts[0]
        self.assertEqual(c.rdtype, dns.rdatatype.RdataType.A)
        self.assertEqual(c.ours.ttl, 600)
        self.assertEqual(c.theirs.ttl, 900)
        self.assertEqual(c.base.ttl, 3600)

    def test_rdata_sets_are_not_unioned(self):
        ours = modify(
            remove={("www", "A")},
            add=("www IN A 1.1.1.1", "www IN A 2.2.2.2"),
        )
        theirs = modify(
            remove={("www", "A")},
            add=("www IN A 1.1.1.1", "www IN A 3.3.3.3"),
        )
        result = dns.zonemerge.try_merge(zone(), ours, theirs)
        self.assertConflicts(result, [dns.zonemerge.ConflictReason.CONFLICTING_CHANGES])

    def test_identical_rdata_sets_resolve(self):
        # Same set, different source order: not a conflict.
        ours = modify(
            remove={("www", "A")},
            add=("www IN A 2.2.2.2", "www IN A 1.1.1.1"),
        )
        theirs = modify(
            remove={("www", "A")},
            add=("www IN A 1.1.1.1", "www IN A 2.2.2.2"),
        )
        merged = dns.zonemerge.merge(zone(), ours, theirs)
        self.assertEqual(
            {r.address for r in merged.get_rdataset("www", "A")},
            {"1.1.1.1", "2.2.2.2"},
        )

    def test_delete_vs_modify_conflict(self):
        ours = without(BASE, "ns1", "A")
        theirs = modify(remove={("ns1", "A")}, add=("ns1 IN A 10.0.0.9",))
        result = dns.zonemerge.try_merge(zone(), ours, theirs)
        self.assertConflicts(result, [dns.zonemerge.ConflictReason.DELETE_MODIFY])
        self.assertIsNone(result.conflicts[0].ours)
        self.assertIsNotNone(result.conflicts[0].theirs)

    def test_delete_while_other_side_unchanged_accepts_delete(self):
        ours = without(BASE, "ns1", "A")
        merged = dns.zonemerge.merge(zone(), ours, zone())
        self.assertIsNone(merged.get_rdataset("ns1", "A"))

    def test_both_delete_accepts_delete(self):
        ours = without(BASE, "ns1", "A")
        merged = dns.zonemerge.merge(zone(), ours, ours)
        self.assertIsNone(merged.get_rdataset("ns1", "A"))

    def test_single_sided_add_accepts(self):
        # New in base absence (relative to a stripped base).
        base = BASE.replace("www IN A 1.1.1.1\n", "")
        ours = zone(base)
        theirs = zone()  # adds www back
        merged = dns.zonemerge.merge(zone(base), ours, theirs)
        self.assertEqual(merged.get_rdataset("www", "A")[0].address, "1.1.1.1")

    def test_distinct_adds_same_unit_conflict(self):
        base = BASE.replace("www IN A 1.1.1.1\n", "")
        ours = modify(remove={("www", "A")}, add=("www IN A 2.2.2.2",))
        theirs = modify(remove={("www", "A")}, add=("www IN A 3.3.3.3",))
        result = dns.zonemerge.try_merge(zone(base), ours, theirs)
        self.assertConflicts(result, [dns.zonemerge.ConflictReason.CONFLICTING_CHANGES])
        self.assertIsNone(result.conflicts[0].base)

    def test_name_case_and_absoluteness_normalized(self):
        ours = zone()
        theirs = zone(relativize=False)
        with ours.writer() as txn:
            txn.replace(
                "mx",
                dns.rdataset.from_text_list(
                    "in",
                    "mx",
                    300,
                    ["10 MAIL.EXAMPLE."],
                    origin=ours.origin,
                    relativize=False,
                ),
            )
        with theirs.writer() as txn:
            txn.replace(
                "MX",
                dns.rdataset.from_text_list("in", "mx", 300, ["10 mail.example."]),
            )
        merged = dns.zonemerge.merge(zone(), ours, theirs)
        rrset = merged.get_rrset("mx", "MX")
        self.assertEqual(rrset.ttl, 300)
        self.assertEqual(len(rrset), 1)

    def test_covers_is_part_of_identity(self):
        # RRSIG(A) and RRSIG(AAAA) are different merge units, so
        # independently adding each one merges rather than conflicts.
        import dns.rdtypes.ANY.RRSIG

        def sig(covered):
            return dns.rdtypes.ANY.RRSIG.RRSIG(
                dns.rdataclass.IN,
                dns.rdatatype.RRSIG,
                covered,
                13,
                2,
                3600,
                2000000000,
                1000000000,
                12345,
                dns.name.from_text("example."),
                b"\xde\xad\xbe\xef",
            )

        ours = zone()
        theirs = zone()
        with ours.writer() as txn:
            txn.replace("www", dns.rdataset.from_rdata(3600, sig("A")))
        with theirs.writer() as txn:
            txn.replace("www", dns.rdataset.from_rdata(3600, sig("AAAA")))
        merged = dns.zonemerge.merge(zone(), ours, theirs)
        self.assertIsNotNone(merged.get_rdataset("www", "RRSIG", covers="A"))
        self.assertIsNotNone(merged.get_rdataset("www", "RRSIG", covers="AAAA"))


class ZoneConstraintTestCase(unittest.TestCase):
    def test_cname_and_other_type_conflict(self):
        # Base has no www; one branch adds a CNAME, the other an A.
        base_text = BASE.replace("www IN A 1.1.1.1\n", "")
        base = zone(base_text)
        ours = modify(text=base_text, add=("www IN CNAME host-a",))
        theirs = modify(text=base_text, add=("www IN A 1.2.3.4",))
        result = dns.zonemerge.try_merge(base, ours, theirs)
        self.assertIsNone(result.merged)
        reasons = [c.reason for c in result.conflicts]
        self.assertEqual(
            set(reasons),
            {dns.zonemerge.ConflictReason.CNAME_AND_OTHER_DATA},
        )
        reported_types = {c.rdtype for c in result.conflicts}
        self.assertIn(dns.rdatatype.RdataType.A, reported_types)
        self.assertIn(dns.rdatatype.RdataType.CNAME, reported_types)

    def test_cname_with_rrsig_is_allowed(self):
        import dns.rdtypes.ANY.RRSIG

        sig = dns.rdtypes.ANY.RRSIG.RRSIG(
            dns.rdataclass.IN,
            dns.rdatatype.RRSIG,
            dns.rdatatype.CNAME,
            13,
            2,
            3600,
            2000000000,
            1000000000,
            12345,
            dns.name.from_text("example."),
            b"\xde\xad\xbe\xef",
        )
        ours = modify(remove={("www", "A")}, add=("www IN CNAME host-a",))
        with ours.writer() as txn:
            txn.replace("www", dns.rdataset.from_rdata(3600, sig))
        merged = dns.zonemerge.merge(zone(), ours, zone())
        self.assertIsNotNone(merged.get_rdataset("www", "CNAME"))

    def test_cname_with_rrsig_of_other_type_conflicts(self):
        # An RRSIG which covers a non-CNAME type is regular data and
        # may not share a node with a CNAME after the merge.
        import dns.rdtypes.ANY.RRSIG

        base_text = BASE.replace("www IN A 1.1.1.1\n", "")
        ours = modify(text=base_text, add=("www IN CNAME host-a",))
        theirs = zone(base_text)
        sig = dns.rdtypes.ANY.RRSIG.RRSIG(
            dns.rdataclass.IN,
            dns.rdatatype.RRSIG,
            dns.rdatatype.A,
            13,
            2,
            3600,
            2000000000,
            1000000000,
            12345,
            dns.name.from_text("example."),
            b"\xde\xad\xbe\xef",
        )
        with theirs.writer() as txn:
            txn.replace("www", dns.rdataset.from_rdata(3600, sig))
        result = dns.zonemerge.try_merge(zone(base_text), ours, theirs)
        self.assertTrue(
            any(
                c.reason == dns.zonemerge.ConflictReason.CNAME_AND_OTHER_DATA
                for c in result.conflicts
            )
        )

    def test_existing_cname_plus_added_other_conflicts(self):
        # Base has no www; ours adds a CNAME, theirs adds TXT at the
        # same name.  These are different merge units, so the unit merge
        # accepts both, and the node-level constraint rejects them.
        base_text = BASE.replace("www IN A 1.1.1.1\n", "")
        ours = modify(text=base_text, add=("www IN CNAME host-a",))
        theirs = modify(text=base_text, add=('www IN TXT "hello"',))
        result = dns.zonemerge.try_merge(zone(base_text), ours, theirs)
        reasons = {c.reason for c in result.conflicts}
        self.assertIn(dns.zonemerge.ConflictReason.CNAME_AND_OTHER_DATA, reasons)

    def test_origin_cname_conflicts(self):
        ours = zone()
        with ours.writer() as txn:
            txn.replace("@", dns.rdataset.from_text("in", "cname", 3600, "host-a"))
        result = dns.zonemerge.try_merge(zone(), ours, zone())
        self.assertIsNone(result.merged)
        self.assertIn(
            dns.zonemerge.ConflictReason.CNAME_AND_OTHER_DATA,
            {c.reason for c in result.conflicts},
        )

    def test_no_soa_after_both_unchanged_delete(self):
        ours = without(BASE, "@", "SOA")
        result = dns.zonemerge.try_merge(zone(), ours, zone())
        reasons = {c.reason for c in result.conflicts}
        self.assertIn(dns.zonemerge.ConflictReason.NO_SOA, reasons)

    def test_no_ns(self):
        ours = without(BASE, "@", "NS")
        result = dns.zonemerge.try_merge(zone(), ours, zone())
        reasons = {c.reason for c in result.conflicts}
        self.assertIn(dns.zonemerge.ConflictReason.NO_NS, reasons)

    def test_soa_delete_vs_modify_reports_unit_conflict_only(self):
        # If SOA itself is an unresolvable unit conflict, we don't pile
        # an additional origin-level NO_SOA on top.
        ours = without(BASE, "@", "SOA")
        theirs = zone(serial=5)
        result = dns.zonemerge.try_merge(zone(), ours, theirs)
        reasons = [c.reason for c in result.conflicts]
        self.assertEqual(
            reasons,
            [dns.zonemerge.ConflictReason.DELETE_MODIFY],
        )


class SerialPolicyTestCase(unittest.TestCase):
    def test_latest_uses_serial_arithmetic(self):
        # 4294967295 + 10 == 9 in serial arithmetic, so 10 is later.
        merged = dns.zonemerge.merge(
            zone(serial=1),
            zone(serial=0xFFFFFFFF),
            zone(serial=0xFFFFFFFF),
            serial_policy=lambda b, o, t: dns.zonemerge.latest_serial(b, o, 10),
        )
        self.assertEqual(merged.get_soa().serial, 10)

    def test_default_policy_picks_latest_branch_serial(self):
        merged = dns.zonemerge.merge(zone(serial=10), zone(serial=20), zone(serial=20))
        self.assertEqual(merged.get_soa().serial, 20)

    def test_increment_policy_bumps_on_zone_change(self):
        # The branch changes the zone (adds a host); the SOA itself is
        # unchanged, so the policy supplies the bump.
        ours = modify(add=("h IN A 1.2.3.4",), serial=10)
        merged = dns.zonemerge.merge(
            zone(serial=10),
            ours,
            zone(serial=10),
            serial_policy=dns.zonemerge.increment_serial,
        )
        self.assertEqual(merged.get_soa().serial, 11)

    def test_increment_policy_always_bumps(self):
        merged = dns.zonemerge.merge(
            zone(serial=10),
            zone(serial=10),
            zone(serial=10),
            serial_policy=dns.zonemerge.increment_serial,
        )
        self.assertEqual(merged.get_soa().serial, 11)

    def test_regressing_serial_is_conflict(self):
        # A naive max() would accept 20 here; the policy wants 5 which
        # is earlier than both branch serials.
        result = dns.zonemerge.try_merge(
            zone(serial=10),
            zone(serial=20),
            zone(serial=20),
            serial_policy=lambda b, o, t: 5,
        )
        self.assertIsNone(result.merged)
        self.assertEqual(
            result.conflicts[0].reason,
            dns.zonemerge.ConflictReason.INVALID_SERIAL,
        )
        self.assertIn("5", result.conflicts[0].detail)
        self.assertIn("20", result.conflicts[0].detail)


class MergeInterfaceTestCase(unittest.TestCase):
    def test_inputs_are_not_modified(self):
        base = zone()
        ours = modify(add=("host-a IN A 1.2.3.4",))
        theirs = modify(add=("host-b IN A 4.3.2.1",))
        snapshots = [z.to_text() for z in (base, ours, theirs)]
        dns.zonemerge.merge(base, ours, theirs)
        self.assertEqual(snapshots, [z.to_text() for z in (base, ours, theirs)])

    def test_merge_raises_merge_conflicts(self):
        ours = modify(remove={("www", "A")}, add=("www 600 IN A 1.1.1.1",))
        theirs = modify(remove={("www", "A")}, add=("www 900 IN A 1.1.1.1",))
        with self.assertRaises(dns.zonemerge.MergeConflicts) as cm:
            dns.zonemerge.merge(zone(), ours, theirs)
        self.assertEqual(len(cm.exception.conflicts), 1)

    def test_conflict_order_is_stable(self):
        ours = modify(add=("zzz 600 IN A 1.1.1.1", "aaa 600 IN A 2.2.2.2"))
        theirs = modify(add=("zzz 900 IN A 1.1.1.1", "aaa 900 IN A 2.2.2.2"))
        result = dns.zonemerge.try_merge(zone(), ours, theirs)
        names = [c.name for c in result.conflicts]
        self.assertEqual(names, sorted(names))

    def test_conflict_lists_three_values(self):
        ours = modify(remove={("www", "A")}, add=("www 600 IN A 1.1.1.1",))
        theirs = modify(remove={("www", "A")}, add=("www 900 IN A 1.1.1.1",))
        result = dns.zonemerge.try_merge(zone(), ours, theirs)
        conflict = result.conflicts[0]
        for value in (conflict.base, conflict.ours, conflict.theirs):
            self.assertIsInstance(value, dns.rrset.RRset)
        self.assertTrue(conflict.name.is_absolute())

    def test_text_roundtrip_preserves_semantics(self):
        ours = modify(add=("host-a IN A 1.2.3.4", "host-b IN AAAA 2001:db8::1"))
        theirs = modify(add=("host-c IN CNAME host-a",))
        merged = dns.zonemerge.merge(zone(), ours, theirs)
        text = merged.to_text()
        reread = dns.zone.from_text(text, origin="example.")
        self.assertEqual(reread.to_text(), merged.to_text())
        for name, rdataset in merged.iterate_rdatasets():
            other = reread.find_rdataset(name, rdataset.rdtype, rdataset.covers)
            self.assertEqual(other.ttl, rdataset.ttl)
            self.assertEqual(
                sorted(r.to_digestable(reread.origin) for r in other),
                sorted(r.to_digestable(merged.origin) for r in rdataset),
            )

    def test_roundtrip_with_nonrelativized_output(self):
        merged = dns.zonemerge.merge(
            zone(),
            modify(add=("host-a IN A 1.2.3.4",)),
            zone(),
            relativize=False,
        )
        text = merged.to_text()
        reread = dns.zone.from_text(text, origin="example.", relativize=False)
        self.assertEqual(reread.to_text(), merged.to_text())

    def test_mixed_relativity_inputs(self):
        merged = dns.zonemerge.merge(
            zone(relativize=True),
            modify(add=("host-a IN A 1.2.3.4",)),
            zone(relativize=False),
        )
        self.assertEqual(merged.get_rdataset("host-a", "A")[0].address, "1.2.3.4")

    def test_origin_mismatch_is_merge_error(self):
        other = dns.zone.from_text(BASE.replace("example.", "other."), origin="other.")
        with self.assertRaises(dns.zonemerge.MergeError):
            dns.zonemerge.merge(zone(), zone(), other)

    def test_rdclass_mismatch_is_merge_error(self):
        other = dns.zone.Zone("example.", dns.rdataclass.CH)
        with other.writer(True) as txn:
            txn.replace(
                "@", dns.rdataset.from_text("CH", "SOA", 3600, "ns1 hm 1 2 3 4 5")
            )
            txn.replace("@", dns.rdataset.from_text("CH", "NS", 3600, "ns1"))
        with self.assertRaises(dns.zonemerge.MergeError):
            dns.zonemerge.merge(zone(), zone(), other)

    def test_ours_policy_regression_conflicts(self):
        result = dns.zonemerge.try_merge(
            zone(serial=10),
            zone(serial=10),
            zone(serial=20),
            serial_policy=dns.zonemerge.ours_serial,
        )
        self.assertIsNone(result.merged)
        self.assertEqual(
            result.conflicts[0].reason,
            dns.zonemerge.ConflictReason.INVALID_SERIAL,
        )


if __name__ == "__main__":
    unittest.main()
