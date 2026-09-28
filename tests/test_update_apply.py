# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import pytest

import dns.message
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataset
import dns.rdatatype
import dns.update
import dns.versioned
import dns.zone

zone_text = """$TTL 300
$ORIGIN example.
@ IN SOA ns1 admin 1 3600 600 86400 3600
@ IN NS ns1
@ IN NS ns2
@ IN MX 10 mail
ns1 IN A 10.0.0.1
ns2 IN A 10.0.0.2
mail IN A 10.0.0.3
www IN A 10.0.0.10
www IN A 10.0.0.11
alias IN CNAME www
multi IN TXT "alpha"
*.wild IN A 10.0.0.99
"""


@pytest.fixture
def vzone():
    zone = dns.zone.from_text(zone_text, "example.", zone_factory=dns.versioned.Zone)
    zone.set_max_versions(None)
    return zone


def make_update():
    return dns.update.UpdateMessage("example.")


def test_prerequisite_name_in_use(vzone):
    update = make_update()
    update.present("www.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR

    update = make_update()
    update.present("absent.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NXDOMAIN


def test_prerequisite_name_not_in_use(vzone):
    update = make_update()
    update.absent("absent.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR

    update = make_update()
    update.absent("www.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.YXDOMAIN


def test_prerequisite_rrset_exists(vzone):
    update = make_update()
    update.present("www.example.", "A")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR

    update = make_update()
    update.present("www.example.", "AAAA")
    assert dns.update.apply(update, vzone) == dns.rcode.NXRRSET


def test_prerequisite_rrset_not_exists(vzone):
    update = make_update()
    update.absent("www.example.", "AAAA")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR

    update = make_update()
    update.absent("www.example.", "A")
    assert dns.update.apply(update, vzone) == dns.rcode.YXRRSET


def test_prerequisite_value_dependent_is_whole_set(vzone):
    # A subset of the rdata is not a match; the whole set must be equal.
    update = make_update()
    update.present("www.example.", "A", "10.0.0.10")
    assert dns.update.apply(update, vzone) == dns.rcode.NXRRSET

    update = make_update()
    update.present("www.example.", "A", "10.0.0.10", "10.0.0.11")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR

    update = make_update()
    update.present("www.example.", "A", "10.0.0.10", "10.0.0.12")
    assert dns.update.apply(update, vzone) == dns.rcode.NXRRSET


def test_prerequisite_value_dependent_ignores_ttl(vzone):
    # The zone TTL is 300; the prerequisite matches anyway.
    update = make_update()
    update.present("multi.example.", "TXT", "alpha")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR


def test_multi_value_prerequisite_gates_update(vzone):
    update = make_update()
    update.present("multi.example.", "TXT", "alpha", "beta")
    update.add("new.example.", 300, "A", "10.0.0.50")
    update.delete("mail.example.", "A", "10.0.0.3")

    # Take a snapshot of the zone before the update.
    before = vzone.reader()
    try:
        # The "beta" value is not in the zone, so the prerequisite fails
        # and none of the changes happen.
        assert dns.update.apply(update, vzone) == dns.rcode.NXRRSET
        with vzone.reader() as txn:
            assert txn.get("new.example.", "A") is None
            assert txn.get("mail.example.", "A") is not None

        # Make the prerequisite fully match, and apply the same message
        # again.  Now the whole group of changes is visible.
        with vzone.writer() as txn:
            txn.add("multi.example.", 300, dns.rdata.from_text("in", "txt", "beta"))
        assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
        with vzone.reader() as after:
            rdataset = after.get("new.example.", "A")
            assert rdataset is not None
            assert rdataset[0].address == "10.0.0.50"
            assert after.get("mail.example.", "A") is None

        # The snapshot from before the update is unchanged.
        assert before.get("new.example.", "A") is None
        assert before.get("mail.example.", "A") is not None
    finally:
        before.rollback()


def test_reader_snapshot_and_committed_reader(vzone):
    update = make_update()
    update.add("new.example.", 300, "A", "10.0.0.50")
    before = vzone.reader()
    try:
        assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
        with vzone.reader() as after:
            assert after.get("new.example.", "A") is not None
        assert before.get("new.example.", "A") is None
    finally:
        before.rollback()


def test_add_records(vzone):
    update = make_update()
    update.add("new.example.", 600, "A", "10.0.0.60")
    update.add("www.example.", 300, "A", "10.0.0.12")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        rdataset = txn.get("new.example.", "A")
        assert rdataset is not None
        assert rdataset.ttl == 600
        rdataset = txn.get("www.example.", "A")
        assert rdataset is not None
        assert len(rdataset) == 3


def test_delete_rdata(vzone):
    update = make_update()
    update.delete("www.example.", "A", "10.0.0.10")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        rdataset = txn.get("www.example.", "A")
        assert rdataset is not None
        assert len(rdataset) == 1
        assert rdataset[0].address == "10.0.0.11"
        # The TTL of the remaining rdata is preserved.
        assert rdataset.ttl == 300


def test_delete_rrset(vzone):
    update = make_update()
    update.delete("www.example.", "A")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        assert txn.get("www.example.", "A") is None
        assert not txn.name_exists("www.example.")


def test_delete_name(vzone):
    update = make_update()
    update.delete("alias.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        assert not txn.name_exists("alias.example.")


def test_delete_nonexistent_is_noop(vzone):
    update = make_update()
    update.delete("absent.example.", "A", "10.0.0.1")
    update.delete("absent.example.", "A")
    update.delete("absent.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR


def test_apex_soa_cannot_be_deleted(vzone):
    update = make_update()
    update.delete("example.", "SOA", "ns1 admin 1 3600 600 86400 3600")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    assert vzone.get_soa() is not None

    update = make_update()
    update.delete("example.", "SOA")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    assert vzone.get_soa() is not None


def test_apex_ns_cannot_be_emptied(vzone):
    # Deleting the RRset is not allowed.
    update = make_update()
    update.delete("example.", "NS")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        assert txn.get("example.", "NS") is not None

    # Deleting all of the rdata is not allowed either.
    update = make_update()
    update.delete("example.", "NS", "ns1")
    update.delete("example.", "NS", "ns2")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        rdataset = txn.get("example.", "NS")
        assert rdataset is not None
        assert len(rdataset) == 2

    # Deleting some of the rdata is fine.
    update = make_update()
    update.delete("example.", "NS", "ns1")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        rdataset = txn.get("example.", "NS")
        assert rdataset is not None
        assert len(rdataset) == 1


def test_delete_name_at_apex_keeps_soa_and_ns(vzone):
    update = make_update()
    update.delete("example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        assert txn.get("example.", "SOA") is not None
        assert txn.get("example.", "NS") is not None
        assert txn.get("example.", "MX") is None


def test_apex_soa_add_replaces_if_serial_advances(vzone):
    update = make_update()
    update.add("example.", 300, "SOA", "ns1 admin 5 3600 600 86400 3600")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    assert vzone.get_soa().serial == 5

    # A lesser or equal serial does not replace the SOA.
    update = make_update()
    update.add("example.", 300, "SOA", "ns1 admin 3 3600 600 86400 3600")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    assert vzone.get_soa().serial == 5

    update = make_update()
    update.add("example.", 300, "SOA", "ns2 admin 5 3600 600 86400 3600")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    assert vzone.get_soa().serial == 5
    assert vzone.get_soa().mname == dns.name.from_text("ns1", None)


def test_non_apex_soa_add_is_formerr(vzone):
    update = make_update()
    update.add("www.example.", 300, "SOA", "ns1 admin 5 3600 600 86400 3600")
    assert dns.update.apply(update, vzone) == dns.rcode.FORMERR


def test_cname_cannot_coexist_with_other_data(vzone):
    # Adding other data at a CNAME's name is ignored.
    update = make_update()
    update.add("alias.example.", 300, "A", "10.0.0.70")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        assert txn.get("alias.example.", "A") is None
        assert txn.get("alias.example.", "CNAME") is not None

    # Adding a CNAME where other data exists is ignored.
    update = make_update()
    update.add("www.example.", 300, "CNAME", "mail.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        assert txn.get("www.example.", "CNAME") is None
        assert txn.get("www.example.", "A") is not None


def test_wildcard_is_literal(vzone):
    update = make_update()
    update.present("*.wild.example.", "A")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR

    # No wildcard synthesis occurs.
    update = make_update()
    update.present("anything.wild.example.", "A")
    assert dns.update.apply(update, vzone) == dns.rcode.NXRRSET

    update = make_update()
    update.present("anything.wild.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NXDOMAIN


def test_cname_is_not_followed(vzone):
    update = make_update()
    update.present("alias.example.", "A")
    assert dns.update.apply(update, vzone) == dns.rcode.NXRRSET

    update = make_update()
    update.present("alias.example.", "CNAME")
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR


def test_out_of_zone_names(vzone):
    update = make_update()
    update.add("foo.example.org.", 300, "A", "10.0.0.1")
    assert dns.update.apply(update, vzone) == dns.rcode.NOTZONE

    update = make_update()
    update.present("foo.example.org.")
    assert dns.update.apply(update, vzone) == dns.rcode.NOTZONE

    update = make_update()
    update.present("www.example.")
    update.add("foo.example.org.", 300, "A", "10.0.0.1")
    assert dns.update.apply(update, vzone) == dns.rcode.NOTZONE


def test_wrong_zone_name(vzone):
    update = dns.update.UpdateMessage("other.example.")
    assert dns.update.apply(update, vzone) == dns.rcode.NOTAUTH


def test_wrong_zone_class(vzone):
    update = dns.update.UpdateMessage("example.", "CH")
    assert dns.update.apply(update, vzone) == dns.rcode.NOTAUTH


def test_not_an_update(vzone):
    query = dns.message.make_query("example.", "A")
    assert dns.update.apply(query, vzone) == dns.rcode.FORMERR


def test_prerequisite_with_ttl_is_formerr(vzone):
    update = make_update()
    update.present("www.example.", dns.rdataset.from_text("in", "a", 300, "10.0.0.10"))
    assert dns.update.apply(update, vzone) == dns.rcode.FORMERR


def test_add_with_zero_ttl_is_formerr(vzone):
    update = make_update()
    update.add("new.example.", 0, "A", "10.0.0.1")
    assert dns.update.apply(update, vzone) == dns.rcode.FORMERR


def test_message_is_not_modified(vzone):
    update = make_update()
    update.present("www.example.", "A")
    update.add("new.example.", 300, "A", "10.0.0.50")
    wire = update.to_wire()
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR
    assert update.to_wire() == wire
    # The message can be applied again; the result reflects the zone
    # state at the time of application.
    assert dns.update.apply(update, vzone) == dns.rcode.NOERROR


def test_wire_roundtrip(vzone):
    update = make_update()
    update.present("www.example.", "A")
    update.add("new.example.", 300, "A", "10.0.0.50")
    update.delete("www.example.", "A", "10.0.0.10")
    update.delete("alias.example.")
    parsed = dns.message.from_wire(update.to_wire())
    assert dns.update.apply(parsed, vzone) == dns.rcode.NOERROR
    with vzone.reader() as txn:
        assert txn.get("new.example.", "A") is not None
        rdataset = txn.get("www.example.", "A")
        assert rdataset is not None
        assert len(rdataset) == 1
        assert rdataset[0].address == "10.0.0.11"
        assert not txn.name_exists("alias.example.")


def test_plain_zone_too():
    zone = dns.zone.from_text(zone_text, "example.")
    update = make_update()
    update.add("new.example.", 300, "A", "10.0.0.50")
    assert dns.update.apply(update, zone) == dns.rcode.NOERROR
    assert zone.get_rdataset("new.example.", "A") is not None
