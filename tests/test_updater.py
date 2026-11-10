# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import threading

import pytest

import dns.exception
import dns.message
import dns.name
import dns.rdata
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.ttl
import dns.update
import dns.updater
import dns.versioned
import dns.zone

ZONE_TEXT = """$ORIGIN example.
$TTL 3600
@ IN SOA ns1.example. hostmaster.example. 1 7200 3600 86400 300
@ IN NS ns1.example.
@ IN NS ns2.example.
ns1 IN A 10.0.0.1
host IN A 10.0.0.2
host IN A 10.0.0.3
alias IN CNAME host.example.
"""

ORIGIN = dns.name.from_text("example.")


@pytest.fixture
def zone():
    return dns.zone.from_text(ZONE_TEXT, "example.", zone_factory=dns.versioned.Zone)


def snapshot(zone):
    return zone.to_text(relativize=False, sorted=True)


def make_update():
    return dns.update.UpdateMessage("example.")


def rcode_of(update_message, zone, **kwargs):
    with pytest.raises(dns.updater.UpdateError) as exc_info:
        dns.updater.apply(update_message, zone, **kwargs)
    return exc_info.value.rcode


def test_basic_apply(zone):
    update_message = make_update()
    update_message.add("new", 300, "a", "10.0.0.9")
    update_message.delete("host", "a", "10.0.0.2")
    update_message.delete("ns1", "a")
    update_message.delete("gone")
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        assert txn.get("new", "a")[0].address == "10.0.0.9"
        assert txn.get("host", "a")[0].address == "10.0.0.3"
        assert txn.get("ns1", "a") is None


def test_wire_message_round_trip(zone):
    update_message = make_update()
    update_message.present("host", "a", "10.0.0.2")
    update_message.absent("new")
    update_message.add("new", 300, "a", "10.0.0.9")
    update_message.delete("host", "a", "10.0.0.2")
    wire = update_message.to_wire()
    parsed = dns.message.from_wire(wire)
    dns.updater.apply(parsed, zone)
    with zone.reader() as txn:
        assert txn.get("new", "a")[0].address == "10.0.0.9"
        assert txn.get("host", "a")[0].address == "10.0.0.3"


def test_plain_zone_manager():
    plain_zone = dns.zone.from_text(ZONE_TEXT, "example.")
    update_message = make_update()
    update_message.add("plain", 300, "a", "1.1.1.1")
    dns.updater.apply(update_message, plain_zone)
    assert plain_zone.get_rdataset("plain", "a")[0].address == "1.1.1.1"


def test_non_relativized_zone_manager():
    # Managers that keep absolute names (relativize=False) must work too;
    # the entry point adapts names to the manager's relativity setting.
    nonrel_zone = dns.zone.from_text(
        ZONE_TEXT, "example.", relativize=False, zone_factory=dns.versioned.Zone
    )
    update_message = make_update()
    update_message.present("host", "a", "10.0.0.2")
    update_message.add("new.example.", 300, "a", "1.1.1.1")
    update_message.delete("@", "soa")
    update_message.add(
        "@", 3600, "soa", "ns1.example. hostmaster.example. 2 7200 3600 86400 300"
    )
    dns.updater.apply(update_message, nonrel_zone)
    with nonrel_zone.reader() as txn:
        assert txn.get(ORIGIN, "soa")[0].serial == 2
        assert txn.get(dns.name.from_text("new.example."), "a")[0].address == "1.1.1.1"


def test_requires_update_message(zone):
    with pytest.raises(TypeError):
        dns.updater.apply(dns.message.make_query("example.", "a"), zone)


def test_wrong_zone_name(zone):
    update_message = dns.update.UpdateMessage("other.")
    assert rcode_of(update_message, zone) == dns.rcode.NOTAUTH


def test_wrong_zone_class(zone):
    update_message = dns.update.UpdateMessage("example.", rdclass=dns.rdataclass.CH)
    assert rcode_of(update_message, zone) == dns.rcode.NOTAUTH


def test_name_outside_zone(zone):
    update_message = make_update()
    update_message.add("evil.other.", 300, "a", "1.1.1.1")
    assert rcode_of(update_message, zone) == dns.rcode.NOTZONE


def test_prereq_name_outside_zone(zone):
    update_message = make_update()
    update_message.present("evil.other.")
    assert rcode_of(update_message, zone) == dns.rcode.NOTZONE


def test_prereq_name_present(zone):
    update_message = make_update()
    update_message.present("host")
    dns.updater.apply(update_message, zone)

    failing = make_update()
    failing.present("missing")
    assert rcode_of(failing, zone) == dns.rcode.NXDOMAIN


def test_prereq_rrset_present(zone):
    update_message = make_update()
    update_message.present("host", "a")
    dns.updater.apply(update_message, zone)

    failing = make_update()
    failing.present("missing", "a")
    assert rcode_of(failing, zone) == dns.rcode.NXRRSET


def test_prereq_rrset_absent(zone):
    update_message = make_update()
    update_message.absent("missing", "a")
    dns.updater.apply(update_message, zone)

    failing = make_update()
    failing.absent("host", "a")
    assert rcode_of(failing, zone) == dns.rcode.YXRRSET


def test_prereq_name_absent(zone):
    update_message = make_update()
    update_message.absent("missing")
    dns.updater.apply(update_message, zone)

    failing = make_update()
    failing.absent("host")
    assert rcode_of(failing, zone) == dns.rcode.YXDOMAIN


def test_prereq_value_rdata(zone):
    update_message = make_update()
    update_message.present("host", "a", "10.0.0.2")
    dns.updater.apply(update_message, zone)

    failing = make_update()
    failing.present("host", "a", "10.0.0.99")
    assert rcode_of(failing, zone) == dns.rcode.NXRRSET


def test_prereq_value_ignores_ttl(zone):
    # A value-dependent prerequisite compares rdata only, never the TTL.
    update_message = make_update()
    update_message.present("host", "a", "10.0.0.2")
    for rrset in update_message.prerequisite:
        rrset.ttl = 9999
    dns.updater.apply(update_message, zone)


def test_failed_prereq_blocks_updates(zone):
    before = snapshot(zone)
    update_message = make_update()
    update_message.add("new", 300, "a", "10.0.0.9")
    update_message.present("missing", "a")
    assert rcode_of(update_message, zone) == dns.rcode.NXRRSET
    assert snapshot(zone) == before


def test_cname_conflict_add_other_to_cname(zone):
    update_message = make_update()
    update_message.add("alias", 300, "mx", "10 mx.example.")
    assert rcode_of(update_message, zone) == dns.rcode.YXRRSET


def test_cname_conflict_add_cname_to_data(zone):
    update_message = make_update()
    update_message.add("host", 300, "cname", "target.example.")
    assert rcode_of(update_message, zone) == dns.rcode.YXRRSET


def test_cname_conflict_at_apex(zone):
    update_message = make_update()
    update_message.add("@", 300, "cname", "target.example.")
    assert rcode_of(update_message, zone) == dns.rcode.YXRRSET


def test_cname_coexists_with_neutral_types(zone):
    # NSEC is a neutral type and may share a node with a CNAME.
    update_message = make_update()
    update_message.add("alias", 300, "nsec", "next.example.")
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        assert txn.get("alias", "nsec") is not None
        assert txn.get("alias", "cname") is not None


def test_cname_add_at_fresh_name(zone):
    update_message = make_update()
    update_message.add("fresh", 300, "cname", "target.example.")
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        assert txn.get("fresh", "cname") is not None


def test_ttl_mismatch_is_servfail(zone):
    update_message = make_update()
    update_message.add("ns1", 999, "a", "10.0.0.5")
    assert rcode_of(update_message, zone) == dns.rcode.SERVFAIL


def test_ttl_mismatch_does_not_apply_other_rdata(zone):
    before = snapshot(zone)
    update_message = make_update()
    update_message.add("ns1", 999, "a", "10.0.0.5")
    assert rcode_of(update_message, zone) == dns.rcode.SERVFAIL
    assert snapshot(zone) == before


def test_non_origin_soa_rejected(zone):
    update_message = make_update()
    update_message.add("host", 300, "soa", "ns1 hostmaster 1 2 3 4 5")
    assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def test_metaclass_add_rejected(zone):
    update_message = make_update()
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "10.0.0.1")
    rrset = dns.rrset.RRset(
        dns.name.from_text("weird.example."), dns.rdataclass.ANY, dns.rdatatype.A
    )
    # Bypass the normal type check to simulate a malformed message carrying
    # rdata under the ANY metaclass.
    rrset.items[rdata] = None
    rrset.ttl = 300
    update_message.update.append(rrset)
    assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def _malformed_prereq(metaclass, rdtype, rdata=None):
    rrset = dns.rrset.RRset(dns.name.from_text("host.example."), metaclass, rdtype)
    if rdata is not None:
        rrset.items[rdata] = None
    return rrset


def test_prereq_any_with_rdata_is_formerr(zone):
    update_message = make_update()
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "10.0.0.1")
    update_message.prerequisite.append(
        _malformed_prereq(dns.rdataclass.ANY, dns.rdatatype.A, rdata)
    )
    assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def test_prereq_none_with_rdata_is_formerr(zone):
    update_message = make_update()
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "10.0.0.1")
    update_message.prerequisite.append(
        _malformed_prereq(dns.rdataclass.NONE, dns.rdatatype.A, rdata)
    )
    assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def test_prereq_metaclass_with_type_none_is_formerr(zone):
    for metaclass in (dns.rdataclass.ANY, dns.rdataclass.NONE):
        update_message = make_update()
        update_message.prerequisite.append(
            _malformed_prereq(metaclass, dns.rdatatype.NONE)
        )
        assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def test_value_prereq_without_rdata_is_formerr(zone):
    update_message = make_update()
    update_message.prerequisite.append(
        _malformed_prereq(dns.rdataclass.IN, dns.rdatatype.A)
    )
    assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def test_any_delete_with_rdata_is_formerr(zone):
    update_message = make_update()
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "10.0.0.1")
    # Builder messages keep the ANY class; attach rdata to simulate a
    # malformed "delete rrset" RR carrying rdata.
    rrset = dns.rrset.RRset(
        dns.name.from_text("host.example."),
        dns.rdataclass.ANY,
        dns.rdatatype.A,
    )
    rrset.items[rdata] = None
    update_message.update.append(rrset)
    assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def test_none_delete_without_rdata_is_formerr(zone):
    update_message = make_update()
    rrset = dns.rrset.RRset(
        dns.name.from_text("host.example."),
        dns.rdataclass.NONE,
        dns.rdatatype.A,
    )
    update_message.update.append(rrset)
    assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def test_bad_ttl_is_formerr(zone):
    update_message = make_update()
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "10.0.0.1")
    rrset = dns.rrset.RRset(
        dns.name.from_text("fresh.example."), dns.rdataclass.IN, dns.rdatatype.A
    )
    rrset.items[rdata] = None
    rrset.ttl = dns.ttl.MAX_TTL + 1
    update_message.update.append(rrset)
    assert rcode_of(update_message, zone) == dns.rcode.FORMERR


def test_cannot_delete_apex_name(zone):
    update_message = make_update()
    update_message.delete("@")
    assert rcode_of(update_message, zone) == dns.rcode.REFUSED


def test_cannot_delete_apex_soa_rrset(zone):
    update_message = make_update()
    update_message.delete("@", "soa")
    assert rcode_of(update_message, zone) == dns.rcode.REFUSED


def test_cannot_delete_apex_ns_rrset(zone):
    update_message = make_update()
    update_message.delete("@", "ns")
    assert rcode_of(update_message, zone) == dns.rcode.REFUSED


def test_apex_soa_may_be_replaced_in_one_update(zone):
    # RFC 2136 section 3.4.3 allows deleting the apex SOA and adding a
    # replacement in the same request; only ending without one is refused.
    update_message = make_update()
    update_message.delete("@", "soa")
    update_message.add(
        "@", 3600, "soa", "ns1.example. hostmaster.example. 2 7200 3600 86400 300"
    )
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        assert txn.get("@", "soa")[0].serial == 2


def test_apex_ns_may_be_replaced_in_one_update(zone):
    update_message = make_update()
    update_message.delete("@", "ns")
    update_message.add("@", 3600, "ns", "ns3.example.")
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        targets = {rdata.target for rdata in txn.get("@", "ns")}
        assert targets == {dns.name.from_text("ns3", None)}


def test_apex_name_delete_must_be_restored_in_one_update(zone):
    update_message = make_update()
    update_message.delete("@")
    update_message.add(
        "@", 3600, "soa", "ns1.example. hostmaster.example. 2 7200 3600 86400 300"
    )
    update_message.add("@", 3600, "ns", "ns1.example.")
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        assert txn.get("@", "soa")[0].serial == 2


def test_apex_name_delete_restored_without_ns_is_refused(zone):
    before = snapshot(zone)
    update_message = make_update()
    update_message.delete("@")
    update_message.add(
        "@", 3600, "soa", "ns1.example. hostmaster.example. 2 7200 3600 86400 300"
    )
    assert rcode_of(update_message, zone) == dns.rcode.REFUSED
    assert snapshot(zone) == before


def test_value_delete_at_apex_is_allowed(zone):
    update_message = make_update()
    update_message.delete("@", "ns", "ns1.example.")
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        rdataset = txn.get("@", "ns")
        # The zone relativizes names, so the remaining target is "ns2".
        targets = {rdata.target for rdata in rdataset}
        assert targets == {dns.name.from_text("ns2", None)}


def test_delete_rrset_below_apex(zone):
    update_message = make_update()
    update_message.delete("ns1", "a")
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        assert txn.get("ns1", "a") is None


def test_illegal_record_mid_update_rolls_back_everything(zone):
    # The requested demonstration: an illegal record partway through the
    # update section must not leave any partial changes behind.
    before = snapshot(zone)
    update_message = make_update()
    update_message.add("ok1", 300, "a", "10.0.0.10")
    update_message.add("ok2", 300, "a", "10.0.0.11")
    update_message.add("@", 300, "cname", "x.example.")
    update_message.add("ok3", 300, "a", "10.0.0.12")
    assert rcode_of(update_message, zone) == dns.rcode.YXRRSET
    assert snapshot(zone) == before
    with zone.reader() as txn:
        assert txn.get("ok1", "a") is None
        assert txn.get("ok2", "a") is None
        assert txn.get("ok3", "a") is None


def test_illegal_delete_mid_update_rolls_back_everything(zone):
    before = snapshot(zone)
    update_message = make_update()
    update_message.add("ok1", 300, "a", "10.0.0.10")
    update_message.delete("@")
    update_message.add("ok2", 300, "a", "10.0.0.11")
    assert rcode_of(update_message, zone) == dns.rcode.REFUSED
    assert snapshot(zone) == before


def test_admission_callback_rejection_rolls_back(zone):
    before = snapshot(zone)

    def deny(txn):
        raise dns.exception.DeniedByPolicy("updates are not allowed")

    update_message = make_update()
    update_message.add("new", 300, "a", "10.0.0.9")
    with pytest.raises(dns.exception.DeniedByPolicy):
        dns.updater.apply(update_message, zone, transaction_setup=deny)
    assert snapshot(zone) == before


def test_admission_callback_can_install_checks(zone):
    def deny_put(txn, name, rdataset):
        raise dns.exception.DeniedByPolicy("blocked put")

    def limit(txn):
        txn.check_put_rdataset(deny_put)

    update_message = make_update()
    update_message.add("new", 300, "a", "10.0.0.9")
    with pytest.raises(dns.exception.DeniedByPolicy):
        dns.updater.apply(update_message, zone, transaction_setup=limit)
    with zone.reader() as txn:
        assert txn.get("new", "a") is None


def test_message_keyname_is_not_authorization(zone):
    # The entry point never inspects the TSIG key name; a message that still
    # carries a key name is processed like any other once the caller hands it
    # in.  Authentication is the upper layer's job.
    update_message = make_update()
    key = dns.tsig.Key("untrusted-key.", b"secret")
    update_message.use_tsig(key)
    assert update_message.keyname == dns.name.from_text("untrusted-key.")
    update_message.add("new", 300, "a", "10.0.0.9")
    dns.updater.apply(update_message, zone)
    with zone.reader() as txn:
        assert txn.get("new", "a") is not None


def test_competing_updates_have_no_prerequisite_invalidation_window(zone):
    # Two updates computed from the same old state both assume "race" is
    # absent and try to create it with different rdata.  With the prereq and
    # the mutation inside one serialized writer transaction, the loser
    # re-evaluates against the winner's committed state and fails; there is
    # no window in which an old snapshot can make both creates succeed.
    barrier = threading.Barrier(2)
    results = []

    def worker(address):
        update_message = make_update()
        update_message.absent("race")
        update_message.add("race", 300, "a", address)
        barrier.wait()
        try:
            dns.updater.apply(update_message, zone)
            results.append(("ok", address))
        except dns.updater.UpdateError as exc:
            results.append(("fail", exc.rcode))

    threads = [
        threading.Thread(target=worker, args=("10.1.1.1",)),
        threading.Thread(target=worker, args=("10.2.2.2",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    successes = [result for result in results if result[0] == "ok"]
    failures = [result for result in results if result[0] == "fail"]
    assert len(successes) == 1
    assert failures == [("fail", dns.rcode.YXDOMAIN)]
    with zone.reader() as txn:
        rdataset = txn.get("race", "a")
        assert len(rdataset) == 1
        assert rdataset[0].address == successes[0][1]


def test_competing_value_prerequisites_serialize(zone):
    # Both updates require the same active rdata, then replace the rrset.
    # The winner commits; the loser's value prerequisite no longer holds at
    # commit time, so it fails rather than silently overwriting the winner.
    barrier = threading.Barrier(2)
    results = []

    def worker(address):
        update_message = make_update()
        update_message.present("ns1", "a", "10.0.0.1")
        update_message.delete("ns1", "a")
        update_message.add("ns1", 300, "a", address)
        barrier.wait()
        try:
            dns.updater.apply(update_message, zone)
            results.append(("ok", address))
        except dns.updater.UpdateError as exc:
            results.append(("fail", exc.rcode))

    threads = [
        threading.Thread(target=worker, args=("10.1.1.1",)),
        threading.Thread(target=worker, args=("10.2.2.2",)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    successes = [result for result in results if result[0] == "ok"]
    failures = [result for result in results if result[0] == "fail"]
    assert len(successes) == 1
    assert failures == [("fail", dns.rcode.NXRRSET)]
    with zone.reader() as txn:
        rdataset = txn.get("ns1", "a")
        assert len(rdataset) == 1
        assert rdataset[0].address == successes[0][1]
