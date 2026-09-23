# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import pytest

import dns.message
import dns.name
import dns.rcode
import dns.rdataset
import dns.update
import dns.versioned
import dns.zone

zone_text = """$TTL 3600
$ORIGIN example.
@ IN SOA ns1 hostmaster 1 2 3 4 5
@ IN NS ns1
@ IN NS ns2
@ IN TXT "apex text"
ns1 IN A 10.0.0.1
ns2 IN A 10.0.0.2
www IN A 10.0.0.10
www IN A 10.0.0.11
alias IN CNAME www
"""


@pytest.fixture(params=[dns.zone.Zone, dns.versioned.Zone])
def zone(request):
    return dns.zone.from_text(zone_text, zone_factory=request.param)


def make_update():
    return dns.update.UpdateMessage("example.")


def get(zone, name, rdtype):
    with zone.reader() as txn:
        return txn.get(name, rdtype)


def name_exists(zone, name):
    with zone.reader() as txn:
        return txn.name_exists(name)


def current_version_id(zone):
    with zone.reader() as txn:
        return txn.version.id


def test_prerequisite_name_in_use(zone):
    update = make_update()
    update.present("www")
    assert update.apply(zone) == dns.rcode.NOERROR
    update = make_update()
    update.present("nosuch")
    assert update.apply(zone) == dns.rcode.NXDOMAIN


def test_prerequisite_name_not_in_use(zone):
    update = make_update()
    update.absent("nosuch")
    assert update.apply(zone) == dns.rcode.NOERROR
    update = make_update()
    update.absent("www")
    assert update.apply(zone) == dns.rcode.YXDOMAIN


def test_prerequisite_rrset_exists(zone):
    update = make_update()
    update.present("www", "A")
    assert update.apply(zone) == dns.rcode.NOERROR
    update = make_update()
    update.present("www", "MX")
    assert update.apply(zone) == dns.rcode.NXRRSET
    update = make_update()
    update.present("nosuch", "A")
    assert update.apply(zone) == dns.rcode.NXRRSET


def test_prerequisite_rrset_does_not_exist(zone):
    update = make_update()
    update.absent("www", "MX")
    assert update.apply(zone) == dns.rcode.NOERROR
    update = make_update()
    update.absent("www", "A")
    assert update.apply(zone) == dns.rcode.YXRRSET


def test_prerequisite_value_dependent(zone):
    # TTLs and record order are ignored in the comparison.
    update = make_update()
    update.present("www", "A", "10.0.0.11", "10.0.0.10")
    assert update.apply(zone) == dns.rcode.NOERROR
    update = make_update()
    rdataset = dns.rdataset.from_text("in", "a", 7200, "10.0.0.10", "10.0.0.11")
    update.present("www", rdataset)
    assert update.apply(zone) == dns.rcode.NOERROR


def test_prerequisite_value_dependent_not_subset(zone):
    # The prerequisite is a proper subset of the zone's RRset.
    update = make_update()
    update.present("www", "A", "10.0.0.10")
    assert update.apply(zone) == dns.rcode.NXRRSET
    # The zone's RRset is a proper subset of the prerequisite.
    update = make_update()
    update.present("www", "A", "10.0.0.10", "10.0.0.11", "10.0.0.12")
    assert update.apply(zone) == dns.rcode.NXRRSET
    # The name does not exist at all.
    update = make_update()
    update.present("nosuch", "A", "10.0.0.10")
    assert update.apply(zone) == dns.rcode.NXRRSET


def test_prerequisite_out_of_zone(zone):
    update = make_update()
    update.present("elsewhere.other.")
    assert update.apply(zone) == dns.rcode.NOTZONE


def test_add(zone):
    update = make_update()
    update.add("new", 300, "A", "10.0.0.20")
    assert update.apply(zone) == dns.rcode.NOERROR
    expected = dns.rdataset.from_text("in", "a", 300, "10.0.0.20")
    assert get(zone, "new", "A") == expected


def test_add_duplicate_is_ignored(zone):
    update = make_update()
    update.add("www", 300, "A", "10.0.0.10")
    assert update.apply(zone) == dns.rcode.NOERROR
    expected = dns.rdataset.from_text("in", "a", 3600, "10.0.0.10", "10.0.0.11")
    assert get(zone, "www", "A") == expected


def test_delete_rr(zone):
    update = make_update()
    update.delete("www", "A", "10.0.0.10")
    assert update.apply(zone) == dns.rcode.NOERROR
    expected = dns.rdataset.from_text("in", "a", 3600, "10.0.0.11")
    assert get(zone, "www", "A") == expected


def test_delete_missing_rr_is_ignored(zone):
    before = zone.to_text()
    update = make_update()
    update.delete("www", "A", "10.0.0.99")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert zone.to_text() == before


def test_delete_rrset(zone):
    update = make_update()
    update.delete("www", "A")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert not name_exists(zone, "www")


def test_delete_name(zone):
    update = make_update()
    update.delete("www")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert not name_exists(zone, "www")


def test_delete_name_at_apex_preserves_soa_and_ns(zone):
    update = make_update()
    update.delete("example.")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert get(zone, "example.", "SOA") is not None
    assert get(zone, "example.", "NS") is not None
    assert get(zone, "example.", "TXT") is None


def test_delete_soa_is_ignored(zone):
    before = zone.to_text()
    update = make_update()
    update.delete("example.", "SOA")
    assert update.apply(zone) == dns.rcode.NOERROR
    update = make_update()
    update.delete("example.", "SOA", "ns1 hostmaster 1 2 3 4 5")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert zone.to_text() == before


def test_delete_apex_ns_is_ignored(zone):
    before = zone.to_text()
    update = make_update()
    update.delete("example.", "NS")
    assert update.apply(zone) == dns.rcode.NOERROR
    update = make_update()
    update.delete("example.", "NS", "ns1")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert zone.to_text() == before


def test_delete_non_apex_ns_is_allowed(zone):
    update = make_update()
    update.add("sub", 300, "NS", "ns1")
    assert update.apply(zone) == dns.rcode.NOERROR
    update = make_update()
    update.delete("sub", "NS")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert not name_exists(zone, "sub")


def test_add_out_of_zone(zone):
    before = zone.to_text()
    update = make_update()
    update.add("elsewhere.other.", 300, "A", "10.0.0.20")
    assert update.apply(zone) == dns.rcode.NOTZONE
    assert zone.to_text() == before


def test_cname_conflicts(zone):
    # Adding a CNAME where other data exists is ignored.
    update = make_update()
    update.add("www", 300, "CNAME", "ns1")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert get(zone, "www", "CNAME") is None
    assert get(zone, "www", "A") is not None
    # Adding other data where a CNAME exists is ignored.
    update = make_update()
    update.add("alias", 300, "A", "10.0.0.20")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert get(zone, "alias", "A") is None
    assert get(zone, "alias", "CNAME") is not None


def test_add_soa_away_from_apex_is_ignored(zone):
    before = zone.to_text()
    update = make_update()
    update.add("www", 300, "SOA", "ns1 hostmaster 2 2 3 4 5")
    assert update.apply(zone) == dns.rcode.NOERROR
    assert zone.to_text() == before


def test_no_zone_section_is_formerr(zone):
    before = zone.to_text()
    update = dns.update.UpdateMessage()
    assert update.apply(zone) == dns.rcode.FORMERR
    assert zone.to_text() == before


def test_class_mismatch_is_formerr(zone):
    before = zone.to_text()
    update = dns.update.UpdateMessage("example.", rdclass="ch")
    assert update.apply(zone) == dns.rcode.FORMERR
    assert zone.to_text() == before


def test_wrong_zone_is_notauth(zone):
    before = zone.to_text()
    update = dns.update.UpdateMessage("other.")
    update.add("www", 300, "A", "10.0.0.20")
    assert update.apply(zone) == dns.rcode.NOTAUTH
    assert zone.to_text() == before


def test_apply_wire_parsed_message(zone):
    update = make_update()
    update.present("www", "A")
    update.absent("new")
    update.add("new", 300, "A", "10.0.0.20")
    update.delete("alias")
    update.delete("www", "A", "10.0.0.10")
    parsed = dns.message.from_wire(update.to_wire())
    assert parsed.apply(zone) == dns.rcode.NOERROR
    assert get(zone, "new", "A") is not None
    assert not name_exists(zone, "alias")
    expected = dns.rdataset.from_text("in", "a", 3600, "10.0.0.11")
    assert get(zone, "www", "A") == expected


def test_failed_prerequisite_is_atomic(zone):
    # Two updates are built with prerequisites based on the same old RRset.
    # The first succeeds, changing the RRset, so the second must fail and
    # leave the zone and its version unchanged.
    update1 = make_update()
    update1.present("www", "A", "10.0.0.10", "10.0.0.11")
    update1.replace("www", 300, "A", "10.0.0.99")
    assert update1.apply(zone) == dns.rcode.NOERROR
    content = zone.to_text()
    version_id = current_version_id(zone)
    update2 = make_update()
    update2.present("www", "A", "10.0.0.10", "10.0.0.11")
    update2.add("extra", 300, "A", "10.0.0.50")
    assert update2.apply(zone) == dns.rcode.NXRRSET
    assert zone.to_text() == content
    assert current_version_id(zone) == version_id


def test_invalid_update_section_is_atomic(zone):
    # The second operation in the update section is invalid, so the first
    # operation must not be applied either.
    before = zone.to_text()
    version_id = current_version_id(zone)
    update = make_update()
    update.add("good", 300, "A", "10.0.0.20")
    update.add("elsewhere.other.", 300, "A", "10.0.0.21")
    assert update.apply(zone) == dns.rcode.NOTZONE
    assert zone.to_text() == before
    assert current_version_id(zone) == version_id
