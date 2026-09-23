# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import pytest

import dns.rcode
import dns.rdataset
import dns.update
import dns.versioned
import dns.zone

zone_text = """$ORIGIN example.
$TTL 300
@     IN SOA   ns1 admin 1 3600 600 86400 3600
@     IN NS    ns1
@     IN NS    ns2
@     IN MX    10 mail
ns1  IN A     10.0.0.1
ns2  IN A     10.0.0.2
mail IN A     10.0.0.3
www  IN A     10.0.0.5
www  IN A     10.0.0.6
alias IN CNAME www
"""


@pytest.fixture(params=[dns.zone.Zone, dns.versioned.Zone])
def zone(request):
    return dns.zone.from_text(zone_text, zone_factory=request.param)


def make_update():
    return dns.update.UpdateMessage("example.")


def get_rdataset(zone, name, rdtype):
    with zone.reader() as txn:
        return txn.get(name, rdtype)


def name_exists(zone, name):
    with zone.reader() as txn:
        return txn.name_exists(name)


def test_prereq_name_in_use(zone):
    update = make_update()
    update.present("www")
    update.add("www", 300, "A", "10.0.0.7")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    rds = get_rdataset(zone, "www.example.", "A")
    assert rds is not None
    assert set(rds.to_text().splitlines()) == {
        "300 IN A 10.0.0.5",
        "300 IN A 10.0.0.6",
        "300 IN A 10.0.0.7",
    }


def test_prereq_name_in_use_fails(zone):
    before = zone.to_text()
    update = make_update()
    update.present("nonexistent")
    update.add("nonexistent", 300, "A", "10.0.0.7")
    assert dns.update.apply_update(update, zone) == dns.rcode.NXDOMAIN
    assert zone.to_text() == before


def test_prereq_name_not_in_use(zone):
    update = make_update()
    update.absent("new")
    update.add("new", 300, "A", "10.0.0.7")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    assert name_exists(zone, "new.example.")


def test_prereq_name_not_in_use_fails(zone):
    before = zone.to_text()
    update = make_update()
    update.absent("www")
    update.delete("www")
    assert dns.update.apply_update(update, zone) == dns.rcode.YXDOMAIN
    assert zone.to_text() == before


def test_prereq_rrset_exists(zone):
    update = make_update()
    update.present("www", "A")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR


def test_prereq_rrset_exists_fails(zone):
    update = make_update()
    update.present("www", "TXT")
    assert dns.update.apply_update(update, zone) == dns.rcode.NXRRSET


def test_prereq_rrset_not_exists(zone):
    update = make_update()
    update.absent("www", "TXT")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR


def test_prereq_rrset_not_exists_fails(zone):
    update = make_update()
    update.absent("www", "A")
    assert dns.update.apply_update(update, zone) == dns.rcode.YXRRSET


def test_prereq_value_dependent(zone):
    update = make_update()
    update.present("www", "A", "10.0.0.5", "10.0.0.6")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR


def test_prereq_value_dependent_ignores_ttl_and_order(zone):
    rds = dns.rdataset.from_text("IN", "A", 999, "10.0.0.6", "10.0.0.5")
    update = make_update()
    update.present("www", rds)
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR


def test_prereq_value_dependent_subset_fails(zone):
    # A subset of the existing RRs is not equality!
    before = zone.to_text()
    update = make_update()
    update.present("www", "A", "10.0.0.5")
    assert dns.update.apply_update(update, zone) == dns.rcode.NXRRSET
    assert zone.to_text() == before


def test_prereq_value_dependent_superset_fails(zone):
    update = make_update()
    update.present("www", "A", "10.0.0.5", "10.0.0.6", "10.0.0.7")
    assert dns.update.apply_update(update, zone) == dns.rcode.NXRRSET


def test_add_and_delete_rr(zone):
    update = make_update()
    update.add("www", 300, "A", "10.0.0.7")
    update.delete("www", "A", "10.0.0.5")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    rds = get_rdataset(zone, "www.example.", "A")
    assert set(rds.to_text().splitlines()) == {
        "300 IN A 10.0.0.6",
        "300 IN A 10.0.0.7",
    }


def test_delete_rrset(zone):
    update = make_update()
    update.delete("www", "A")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    assert get_rdataset(zone, "www.example.", "A") is None
    assert not name_exists(zone, "www.example.")


def test_delete_name(zone):
    update = make_update()
    update.delete("mail")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    assert not name_exists(zone, "mail.example.")
    # The MX at the apex is untouched.
    assert get_rdataset(zone, "example.", "MX") is not None


def test_delete_name_then_add(zone):
    # Operations are applied in order, each against the result of the
    # previous ones.
    update = make_update()
    update.delete("www")
    update.add("www", 300, "A", "10.0.0.10")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    rds = get_rdataset(zone, "www.example.", "A")
    assert rds.to_text() == "300 IN A 10.0.0.10"


def test_out_of_zone_owner(zone):
    before = zone.to_text()
    update = make_update()
    update.add("other.org.", 300, "A", "10.9.9.9")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOTZONE
    assert zone.to_text() == before


def test_wrong_zone(zone):
    update = dns.update.UpdateMessage("other.org.")
    update.add("www", 300, "A", "10.0.0.7")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOTAUTH


def test_no_zone_section(zone):
    update = dns.update.UpdateMessage()
    assert dns.update.apply_update(update, zone) == dns.rcode.FORMERR


def test_wrong_zone_class(zone):
    update = dns.update.UpdateMessage("example.", rdclass="CH")
    assert dns.update.apply_update(update, zone) == dns.rcode.FORMERR


def test_cname_conflict_add_cname(zone):
    # Adding a CNAME where other data exists is ignored.
    update = make_update()
    update.add("www", 300, "CNAME", "mail")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    assert get_rdataset(zone, "www.example.", "CNAME") is None
    assert get_rdataset(zone, "www.example.", "A") is not None


def test_cname_conflict_add_other_data(zone):
    # Adding other data where a CNAME exists is ignored.
    update = make_update()
    update.add("alias", 300, "A", "10.0.0.9")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    assert get_rdataset(zone, "alias.example.", "A") is None
    assert get_rdataset(zone, "alias.example.", "CNAME") is not None


def test_apex_soa_cannot_be_deleted(zone):
    update = make_update()
    update.delete("example.", "SOA")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    assert get_rdataset(zone, "example.", "SOA") is not None


def test_apex_soa_rr_cannot_be_deleted(zone):
    update = make_update()
    update.delete("example.", "SOA", "ns1 admin 1 3600 600 86400 3600")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    assert get_rdataset(zone, "example.", "SOA") is not None


def test_apex_ns_rrset_cannot_be_deleted(zone):
    update = make_update()
    update.delete("example.", "NS")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    rds = get_rdataset(zone, "example.", "NS")
    assert rds is not None
    assert len(rds) == 2


def test_apex_ns_rr_deletion(zone):
    # Deleting one of two apex NS RRs is fine.
    update = make_update()
    update.delete("example.", "NS", "ns2")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    rds = get_rdataset(zone, "example.", "NS")
    assert rds.to_text() == "300 IN NS ns1"


def test_apex_last_ns_rr_cannot_be_deleted(zone):
    # Deleting both apex NS RRs in one update leaves the last one.
    update = make_update()
    update.delete("example.", "NS", "ns2")
    update.delete("example.", "NS", "ns1")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    rds = get_rdataset(zone, "example.", "NS")
    assert rds.to_text() == "300 IN NS ns1"


def test_delete_all_at_apex_preserves_soa_and_ns(zone):
    update = make_update()
    update.delete("example.")
    assert dns.update.apply_update(update, zone) == dns.rcode.NOERROR
    assert get_rdataset(zone, "example.", "SOA") is not None
    assert get_rdataset(zone, "example.", "NS") is not None
    assert get_rdataset(zone, "example.", "MX") is None


def test_competing_updates(zone):
    # Two updates are prepared against the same old version of the www
    # RRset.  The first one wins; the second one fails its prerequisite
    # and leaves the zone (and its versions) untouched.
    old = dns.rdataset.from_text("IN", "A", 300, "10.0.0.5", "10.0.0.6")
    update1 = make_update()
    update1.present("www", old)
    update1.replace("www", 300, "A", "10.0.0.7")
    update2 = make_update()
    update2.present("www", old)
    update2.replace("www", 300, "A", "10.0.0.8")
    assert dns.update.apply_update(update1, zone) == dns.rcode.NOERROR
    after_first = zone.to_text()
    if isinstance(zone, dns.versioned.Zone):
        versions_after_first = [v.id for v in zone._versions]
    assert dns.update.apply_update(update2, zone) == dns.rcode.NXRRSET
    assert zone.to_text() == after_first
    rds = get_rdataset(zone, "www.example.", "A")
    assert rds.to_text() == "300 IN A 10.0.0.7"
    if isinstance(zone, dns.versioned.Zone):
        assert [v.id for v in zone._versions] == versions_after_first


def test_failed_update_is_atomic(zone):
    # A message whose later operations are invalid leaves no residue
    # from its earlier operations.
    before = zone.to_text()
    if isinstance(zone, dns.versioned.Zone):
        versions_before = [v.id for v in zone._versions]
    update = make_update()
    update.add("newhost", 300, "A", "10.0.0.9")
    update.delete("mail")
    update.add("other.org.", 300, "A", "10.9.9.9")  # not in the zone
    assert dns.update.apply_update(update, zone) == dns.rcode.NOTZONE
    assert zone.to_text() == before
    assert not name_exists(zone, "newhost.example.")
    assert name_exists(zone, "mail.example.")
    if isinstance(zone, dns.versioned.Zone):
        assert [v.id for v in zone._versions] == versions_before


def test_wire_round_trip(zone):
    # A parsed update message applies just like a constructed one.
    update = make_update()
    update.present("www", "A", "10.0.0.5", "10.0.0.6")
    update.add("www", 300, "A", "10.0.0.7")
    update.delete("mail", "A", "10.0.0.3")
    parsed = dns.message.from_wire(update.to_wire())
    assert dns.update.apply_update(parsed, zone) == dns.rcode.NOERROR
    rds = get_rdataset(zone, "www.example.", "A")
    assert len(rds) == 3
    assert not name_exists(zone, "mail.example.")


def test_wire_prereq_failure(zone):
    before = zone.to_text()
    update = make_update()
    update.absent("www")
    update.delete("www")
    parsed = dns.message.from_wire(update.to_wire())
    assert dns.update.apply_update(parsed, zone) == dns.rcode.YXDOMAIN
    assert zone.to_text() == before
