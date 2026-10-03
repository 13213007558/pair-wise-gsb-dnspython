# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import pytest

import dns.name
import dns.rdatatype
import dns.zone
import dns.zonemerge

ORIGIN = "example.com."

BASE_TEXT = """$ORIGIN example.com.
@ 300 IN SOA ns1 admin 1 3600 600 86400 300
@ 300 IN NS ns1
@ 300 IN NS ns2
www 300 IN A 192.0.2.1
mail 300 IN A 192.0.2.25
mail 300 IN MX 10 mail
"""


def make_zone(text, check_origin=False):
    return dns.zone.from_text(text, ORIGIN, check_origin=check_origin)


def merge(base_text, ours_text, theirs_text, **kw):
    return dns.zonemerge.merge_zones(
        make_zone(base_text), make_zone(ours_text), make_zone(theirs_text), **kw
    )


def rrset_texts(zone):
    """All (owner, type, ttl, rdata) tuples in a canonical form."""
    items = set()
    for name, node in zone.items():
        owner = name.derelativize(zone.origin).canonicalize().to_text()
        for rds in node.rdatasets:
            for rd in rds:
                items.add(
                    (
                        owner,
                        dns.rdatatype.to_text(rds.rdtype),
                        rds.ttl,
                        rd.to_digestable(zone.origin),
                    )
                )
    return items


def test_different_hosts_merge():
    ours = BASE_TEXT + "host1 300 IN A 192.0.2.10\n"
    theirs = BASE_TEXT + "host2 300 IN A 192.0.2.20\n"
    result = merge(BASE_TEXT, ours, theirs)
    assert result.ok
    assert result.conflicts == []
    zone = result.zone
    assert zone is not None
    assert zone.get_rdataset("host1", "A") is not None
    assert zone.get_rdataset("host2", "A") is not None
    assert zone.get_rdataset("www", "A") is not None


def test_one_side_modify_accepted():
    ours = BASE_TEXT.replace("www 300 IN A", "www 400 IN A")
    result = merge(BASE_TEXT, ours, BASE_TEXT)
    assert result.ok
    rds = result.zone.get_rdataset("www", "A")
    assert rds.ttl == 400


def test_both_sides_same_change_accepted():
    changed = BASE_TEXT.replace("www 300 IN A", "www 400 IN A")
    result = merge(BASE_TEXT, changed, changed)
    assert result.ok
    assert result.zone.get_rdataset("www", "A").ttl == 400


def test_ttl_conflict():
    ours = BASE_TEXT.replace("www 300 IN A", "www 400 IN A")
    theirs = BASE_TEXT.replace("www 300 IN A", "www 500 IN A")
    result = merge(BASE_TEXT, ours, theirs)
    assert not result.ok
    assert result.zone is None
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.reason == dns.zonemerge.ConflictReason.BOTH_MODIFIED
    assert conflict.key.owner == dns.name.from_text("www.example.com.")
    assert conflict.key.rdtype == dns.rdatatype.A
    assert conflict.base.ttl == 300
    assert conflict.ours.ttl == 400
    assert conflict.theirs.ttl == 500


def test_rdata_conflict_not_unioned():
    ours = BASE_TEXT.replace(
        "www 300 IN A 192.0.2.1", "www 300 IN A 192.0.2.1\nwww 300 IN A 192.0.2.2"
    )
    theirs = BASE_TEXT.replace(
        "www 300 IN A 192.0.2.1", "www 300 IN A 192.0.2.1\nwww 300 IN A 192.0.2.3"
    )
    result = merge(BASE_TEXT, ours, theirs)
    assert not result.ok
    assert len(result.conflicts) == 1
    assert result.conflicts[0].reason == dns.zonemerge.ConflictReason.BOTH_MODIFIED


def test_delete_vs_modify():
    ours = BASE_TEXT.replace("mail 300 IN A 192.0.2.25\n", "")
    theirs = BASE_TEXT.replace("mail 300 IN A", "mail 400 IN A")
    result = merge(BASE_TEXT, ours, theirs)
    assert not result.ok
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.reason == dns.zonemerge.ConflictReason.DELETE_VS_MODIFY
    assert conflict.base is not None
    assert conflict.ours is None
    assert conflict.theirs is not None


def test_delete_vs_untouched_is_deleted():
    ours = BASE_TEXT.replace("mail 300 IN A 192.0.2.25\n", "")
    result = merge(BASE_TEXT, ours, BASE_TEXT)
    assert result.ok
    assert result.zone.get_rdataset("mail", "A") is None
    # The MX at the same name is untouched.
    assert result.zone.get_rdataset("mail", "MX") is not None


def test_both_delete_accepted():
    changed = BASE_TEXT.replace("mail 300 IN A 192.0.2.25\n", "")
    result = merge(BASE_TEXT, changed, changed)
    assert result.ok
    assert result.zone.get_rdataset("mail", "A") is None


def test_case_and_relativity_no_false_conflict():
    # Same content as base, but with different case and absolute names.
    variant = """$ORIGIN example.com.
@ 300 IN SOA ns1 admin 1 3600 600 86400 300
@ 300 IN NS ns1
@ 300 IN NS ns2
WWW 300 IN A 192.0.2.1
MAIL.example.com. 300 IN A 192.0.2.25
mail 300 IN MX 10 MAIL.example.com.
host1 300 IN A 192.0.2.10
"""
    result = merge(BASE_TEXT, variant, BASE_TEXT)
    assert result.ok
    # The only changes are the added host1 and the serial policy bump.
    remaining = rrset_texts(result.zone) - rrset_texts(make_zone(BASE_TEXT))
    remaining = {item for item in remaining if item[1] != "SOA"}
    assert len(remaining) == 1
    owner, rdtype, _, _ = next(iter(remaining))
    assert owner == "host1.example.com."
    assert rdtype == "A"


def test_rdata_order_no_false_conflict():
    reordered = """$ORIGIN example.com.
@ 300 IN SOA ns1 admin 1 3600 600 86400 300
@ 300 IN NS ns2
@ 300 IN NS ns1
mail 300 IN MX 10 mail
mail 300 IN A 192.0.2.25
www 300 IN A 192.0.2.1
"""
    result = merge(BASE_TEXT, reordered, BASE_TEXT)
    assert result.ok
    assert result.conflicts == []


def test_cname_and_other_data_conflict():
    ours = BASE_TEXT + "alias 300 IN CNAME www\n"
    theirs = BASE_TEXT + "alias 300 IN A 192.0.2.99\n"
    result = merge(BASE_TEXT, ours, theirs)
    assert not result.ok
    reasons = {c.reason for c in result.conflicts}
    assert reasons == {dns.zonemerge.ConflictReason.CNAME_AND_OTHER_DATA}
    rdtypes = {c.key.rdtype for c in result.conflicts}
    assert rdtypes == {dns.rdatatype.CNAME, dns.rdatatype.A}
    for conflict in result.conflicts:
        assert conflict.key.owner == dns.name.from_text("alias.example.com.")


def test_cname_and_neutral_coexist():
    ours = BASE_TEXT + "alias 300 IN CNAME www\n"
    theirs = BASE_TEXT + "alias 300 IN NSEC x A\n"
    result = merge(BASE_TEXT, ours, theirs)
    assert result.ok


def test_default_serial_policy_increments():
    result = merge(BASE_TEXT, BASE_TEXT, BASE_TEXT)
    assert result.ok
    assert result.zone.get_soa().serial == 2


def test_serial_policy_callable():
    result = merge(
        BASE_TEXT, BASE_TEXT, BASE_TEXT, serial_policy=lambda b, o, t: b + 10
    )
    assert result.ok
    assert result.zone.get_soa().serial == 11


def test_serial_policy_int():
    result = merge(BASE_TEXT, BASE_TEXT, BASE_TEXT, serial_policy=2026092301)
    assert result.ok
    assert result.zone.get_soa().serial == 2026092301


def test_serial_policy_wraps():
    base = BASE_TEXT.replace(
        "@ 300 IN SOA ns1 admin 1 ", "@ 300 IN SOA ns1 admin 4294967295 "
    )
    result = merge(base, base, base)
    assert result.ok
    assert result.zone.get_soa().serial == 0


def test_serial_policy_not_numeric_max():
    # A policy that simply takes the numeric maximum is not necessarily
    # valid in serial arithmetic; here the maximum is "less" than the
    # base serial and must be rejected.
    base = BASE_TEXT.replace(
        "@ 300 IN SOA ns1 admin 1 ", "@ 300 IN SOA ns1 admin 4294967295 "
    )
    with pytest.raises(dns.zonemerge.BadSerial):
        merge(base, base, base, serial_policy=lambda b, o, t: max(b, o, t))


def test_serial_policy_must_advance():
    with pytest.raises(dns.zonemerge.BadSerial):
        merge(BASE_TEXT, BASE_TEXT, BASE_TEXT, serial_policy=lambda b, o, t: b)
    with pytest.raises(dns.zonemerge.BadSerial):
        merge(BASE_TEXT, BASE_TEXT, BASE_TEXT, serial_policy=1)


def test_soa_serial_both_bumped_differently_conflicts():
    ours = BASE_TEXT.replace("admin 1 ", "admin 5 ")
    theirs = BASE_TEXT.replace("admin 1 ", "admin 7 ")
    result = merge(BASE_TEXT, ours, theirs)
    assert not result.ok
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.reason == dns.zonemerge.ConflictReason.BOTH_MODIFIED
    assert conflict.key.rdtype == dns.rdatatype.SOA


def test_missing_ns_conflict():
    theirs = BASE_TEXT.replace("@ 300 IN NS ns1\n", "").replace(
        "@ 300 IN NS ns2\n", ""
    )
    result = merge(BASE_TEXT, BASE_TEXT, theirs)
    assert not result.ok
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.reason == dns.zonemerge.ConflictReason.MISSING_NS
    assert conflict.key.rdtype == dns.rdatatype.NS
    assert conflict.base is not None
    assert conflict.theirs is None


def test_missing_soa_conflict():
    theirs = BASE_TEXT.replace("@ 300 IN SOA ns1 admin 1 3600 600 86400 300\n", "")
    result = merge(BASE_TEXT, BASE_TEXT, theirs)
    assert not result.ok
    reasons = [c.reason for c in result.conflicts]
    assert reasons == [dns.zonemerge.ConflictReason.MISSING_SOA]


def test_conflict_order_is_stable():
    ours = BASE_TEXT.replace("www 300 IN A", "www 400 IN A").replace(
        "mail 300 IN A", "mail 400 IN A"
    )
    theirs = BASE_TEXT.replace("www 300 IN A", "www 500 IN A").replace(
        "mail 300 IN A", "mail 500 IN A"
    )
    result1 = merge(BASE_TEXT, ours, theirs)
    result2 = merge(BASE_TEXT, theirs, ours)
    assert not result1.ok
    assert len(result1.conflicts) == 2
    owners = [c.key.owner for c in result1.conflicts]
    assert owners == sorted(owners)
    # Same conflicts, in the same order, regardless of side ordering.
    assert [str(c.key) for c in result1.conflicts] == [
        str(c.key) for c in result2.conflicts
    ]


def test_inputs_not_modified():
    ours = BASE_TEXT + "host1 300 IN A 192.0.2.10\n"
    theirs = BASE_TEXT + "host2 300 IN A 192.0.2.20\n"
    base_zone = make_zone(BASE_TEXT)
    ours_zone = make_zone(ours)
    theirs_zone = make_zone(theirs)
    snapshots = [z.to_text() for z in (base_zone, ours_zone, theirs_zone)]
    result = dns.zonemerge.merge_zones(base_zone, ours_zone, theirs_zone)
    assert result.ok
    assert [z.to_text() for z in (base_zone, ours_zone, theirs_zone)] == snapshots
    # Mutating the merged zone must not affect the inputs.
    result.zone.delete_node("host1")
    assert [z.to_text() for z in (base_zone, ours_zone, theirs_zone)] == snapshots


def test_incompatible_origins():
    other = dns.zone.from_text(BASE_TEXT, "example.org.", check_origin=False)
    with pytest.raises(dns.zonemerge.IncompatibleZones):
        dns.zonemerge.merge_zones(make_zone(BASE_TEXT), other, other)


def test_round_trip_preserves_semantics():
    ours = BASE_TEXT + "host1 300 IN A 192.0.2.10\n"
    theirs = BASE_TEXT.replace("www 300 IN A", "www 400 IN A")
    result = merge(BASE_TEXT, ours, theirs)
    assert result.ok
    text = result.zone.to_text()
    reread = dns.zone.from_text(text, ORIGIN)
    assert rrset_texts(reread) == rrset_texts(result.zone)
    # And a merge of the reread zone against itself only advances the
    # serial, per the serial policy.
    result2 = dns.zonemerge.merge_zones(result.zone, reread, reread)
    assert result2.ok
    without_soa = {
        item for item in rrset_texts(result2.zone) if item[1] != "SOA"
    }
    assert without_soa == {
        item for item in rrset_texts(result.zone) if item[1] != "SOA"
    }
    assert result2.zone.get_soa().serial == result.zone.get_soa().serial + 1


def test_conflict_str():
    ours = BASE_TEXT.replace("www 300 IN A", "www 400 IN A")
    theirs = BASE_TEXT.replace("www 300 IN A", "www 500 IN A")
    result = merge(BASE_TEXT, ours, theirs)
    text = str(result.conflicts[0])
    assert "www.example.com." in text
    assert "both-modified" in text
    assert "400" in text
    assert "500" in text
