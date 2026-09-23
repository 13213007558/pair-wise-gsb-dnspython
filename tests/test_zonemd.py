# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import pytest

import dns.name
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.zone
import dns.zonemd
from dns.zonetypes import DigestHashAlgorithm

SOA_SERIAL = 2018031900
SOA_TTL = 86400


def add_rrset(zone, name, ttl, rdtype, *rdatas):
    rrset = dns.rrset.from_text(name, ttl, "IN", rdtype, *rdatas)
    zone.replace_rdataset(rrset.name, rrset)


def make_zone(relativize=True, reverse=False, uppercase=False):
    zone = dns.zone.Zone("example.", relativize=relativize)
    ns1 = "NS1.EXAMPLE." if uppercase else "ns1.example."
    mx = "MAIL2.EXAMPLE." if uppercase else "mail2.example."
    rrsets = [
        (
            "example.",
            SOA_TTL,
            "SOA",
            (f"ns1.example. admin.example. {SOA_SERIAL} 1800 900 604800 86400",),
        ),
        ("example.", 86400, "NS", ("ns1.example.", "ns2.example.")),
        (ns1, 3600, "A", ("203.0.113.63",)),
        ("ns2.example.", 3600, "AAAA", ("2001:db8::63",)),
        ("mail.example.", 3600, "MX", (f"10 {mx}",)),
    ]
    if reverse:
        rrsets.reverse()
    for name, ttl, rdtype, rdatas in rrsets:
        add_rrset(zone, name, ttl, rdtype, *rdatas)
    return zone


def add_rrsig(zone, name, covered):
    rrset = dns.rrset.from_text(
        name,
        86400,
        "IN",
        "RRSIG",
        f"{covered} 1 1 86400 20300101000000 20200101000000 12345 example. AAAA",
    )
    rdataset = dns.rdataset.Rdataset(rrset.rdclass, rrset.rdtype, rrset[0].covers())
    rdataset.update_ttl(86400)
    rdataset.update(rrset)
    zone.replace_rdataset(rrset.name, rdataset)


def diagnostics(statuses):
    return [s.diagnostic for s in statuses]


def test_compute_does_not_modify_zone():
    zone = make_zone()
    before = zone.to_text()
    dns.zonemd.compute_zonemd(zone)
    assert zone.to_text() == before
    assert zone.get_rdataset("example.", "ZONEMD") is None


def test_compute_selectable_parameters():
    zone = make_zone()
    zonemd = dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA512, serial=42)
    assert zonemd.serial == 42
    assert zonemd.scheme == 1
    assert zonemd.hash_algorithm == DigestHashAlgorithm.SHA512
    assert len(zonemd.digest) == 64
    # Integer algorithm and scheme values are accepted too.
    zonemd2 = dns.zonemd.compute_zonemd(zone, 2, 1, serial=42)
    assert zonemd == zonemd2


def test_attach_adds_rrset_and_replaces():
    zone = make_zone()
    zonemd = dns.zonemd.compute_zonemd(zone, attach=True)
    rds = zone.get_rdataset("example.", "ZONEMD")
    assert rds is not None
    assert rds.ttl == SOA_TTL
    assert list(rds) == [zonemd]
    # Attaching again replaces the previous RRset.
    zonemd2 = dns.zonemd.compute_zonemd(
        zone, DigestHashAlgorithm.SHA512, ttl=300, attach=True
    )
    rds = zone.get_rdataset("example.", "ZONEMD")
    assert rds is not None
    assert rds.ttl == 300
    assert list(rds) == [zonemd2]


@pytest.mark.parametrize(
    "algorithm", [DigestHashAlgorithm.SHA384, DigestHashAlgorithm.SHA512]
)
@pytest.mark.parametrize("relativize", [True, False])
def test_write_read_verify_roundtrip(algorithm, relativize):
    zone = make_zone(relativize=relativize)
    dns.zonemd.compute_zonemd(zone, algorithm, attach=True)
    text = zone.to_text()
    zone2 = dns.zone.from_text(text, "example.", relativize=relativize)
    statuses = dns.zonemd.verify_zonemd(zone2)
    assert len(statuses) == 1
    assert statuses[0].ok
    assert statuses[0].diagnostic == dns.zonemd.ZonemdDiagnostic.OK


def test_equivalent_representations_same_digest():
    zone = make_zone()
    digest = dns.zonemd.compute_zonemd(zone)
    # Node insertion order does not matter.
    assert dns.zonemd.compute_zonemd(make_zone(reverse=True)) == digest
    # Owner and rdata name case does not matter.
    assert dns.zonemd.compute_zonemd(make_zone(uppercase=True)) == digest
    # The TTL of the (excluded) ZONEMD RRset does not matter.
    for ttl in (0, 300, 86400):
        zoned = make_zone()
        dns.zonemd.compute_zonemd(zoned, ttl=ttl, attach=True)
        assert dns.zonemd.compute_zonemd(zoned) == digest


def test_rdata_change_fails_verification():
    zone = make_zone()
    dns.zonemd.compute_zonemd(zone, attach=True)
    add_rrset(zone, "ns1.example.", 3600, "A", "203.0.113.64")
    assert diagnostics(dns.zonemd.verify_zonemd(zone)) == [
        dns.zonemd.ZonemdDiagnostic.DIGEST_MISMATCH
    ]


def test_serial_change_fails_verification():
    zone = make_zone()
    dns.zonemd.compute_zonemd(zone, attach=True)
    add_rrset(
        zone,
        "example.",
        SOA_TTL,
        "SOA",
        f"ns1.example. admin.example. {SOA_SERIAL + 1} 1800 900 604800 86400",
    )
    assert diagnostics(dns.zonemd.verify_zonemd(zone)) == [
        dns.zonemd.ZonemdDiagnostic.SERIAL_MISMATCH
    ]


def test_bad_digest():
    zone = make_zone()
    zonemd = dns.zonemd.compute_zonemd(zone)
    bad = bytes([zonemd.digest[0] ^ 0xFF]) + zonemd.digest[1:]
    bad_zonemd = dns.rdata.from_text("IN", "ZONEMD", f"{zonemd.serial} 1 1 {bad.hex()}")
    statuses = dns.zonemd.verify_zonemd(zone, bad_zonemd)
    assert diagnostics(statuses) == [dns.zonemd.ZonemdDiagnostic.DIGEST_MISMATCH]
    assert not statuses[0].ok
    assert statuses[0].zonemd == bad_zonemd


def test_multiple_zonemd_verified_individually():
    zone = make_zone()
    good384 = dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA384)
    good512 = dns.zonemd.compute_zonemd(zone, DigestHashAlgorithm.SHA512)
    bad = dns.rdata.from_text("IN", "ZONEMD", f"{SOA_SERIAL} 1 1 " + "ab" * 48)
    rrset = dns.rrset.RRset(dns.name.empty, dns.rdataclass.IN, dns.rdatatype.ZONEMD)
    rrset.add(good384, SOA_TTL)
    rrset.add(good512, SOA_TTL)
    rrset.add(bad, SOA_TTL)
    zone.replace_rdataset(dns.name.empty, rrset)
    statuses = dns.zonemd.verify_zonemd(zone)
    assert len(statuses) == 3
    assert sorted(diagnostics(statuses)) == sorted(
        [
            dns.zonemd.ZonemdDiagnostic.OK,
            dns.zonemd.ZonemdDiagnostic.OK,
            dns.zonemd.ZonemdDiagnostic.DIGEST_MISMATCH,
        ]
    )
    # An explicit iterable of zonemd rdatas can be verified too.
    statuses = dns.zonemd.verify_zonemd(zone, [good384, bad])
    assert diagnostics(statuses) == [
        dns.zonemd.ZonemdDiagnostic.OK,
        dns.zonemd.ZonemdDiagnostic.DIGEST_MISMATCH,
    ]


def test_unsupported_scheme_and_hash_algorithm():
    zone = make_zone()
    bad_scheme = dns.rdata.from_text("IN", "ZONEMD", f"{SOA_SERIAL} 2 1 " + "ab" * 48)
    bad_algorithm = dns.rdata.from_text(
        "IN", "ZONEMD", f"{SOA_SERIAL} 1 240 " + "ab" * 16
    )
    statuses = dns.zonemd.verify_zonemd(zone, [bad_scheme, bad_algorithm])
    assert diagnostics(statuses) == [
        dns.zonemd.ZonemdDiagnostic.UNSUPPORTED_SCHEME,
        dns.zonemd.ZonemdDiagnostic.UNSUPPORTED_HASH_ALGORITHM,
    ]
    with pytest.raises(dns.zone.UnsupportedDigestScheme):
        dns.zonemd.compute_zonemd(zone, scheme=2)
    with pytest.raises(dns.zone.UnsupportedDigestHashAlgorithm):
        dns.zonemd.compute_zonemd(zone, hash_algorithm=240)


def test_no_origin():
    zone = dns.zone.Zone(None)
    statuses = dns.zonemd.verify_zonemd(zone)
    assert diagnostics(statuses) == [dns.zonemd.ZonemdDiagnostic.NO_ORIGIN]
    assert statuses[0].zonemd is None
    with pytest.raises(dns.zone.UnknownOrigin):
        dns.zonemd.compute_zonemd(zone)


def test_no_soa():
    zone = dns.zone.Zone("example.")
    add_rrset(zone, "example.", 86400, "NS", "ns1.example.")
    with pytest.raises(dns.zone.NoSOA):
        dns.zonemd.compute_zonemd(zone)
    # An explicit serial avoids the need for an SOA when computing.
    zonemd = dns.zonemd.compute_zonemd(zone, serial=SOA_SERIAL)
    # Verification needs the SOA to compare serials.
    statuses = dns.zonemd.verify_zonemd(zone, zonemd)
    assert diagnostics(statuses) == [dns.zonemd.ZonemdDiagnostic.NO_SOA]


def test_no_zonemd():
    zone = make_zone()
    statuses = dns.zonemd.verify_zonemd(zone)
    assert diagnostics(statuses) == [dns.zonemd.ZonemdDiagnostic.NO_ZONEMD]
    assert statuses[0].zonemd is None


def test_size_limit():
    zone = make_zone()
    digest = dns.zonemd.compute_zonemd(zone)
    # A generous budget computes the same digest.
    assert dns.zonemd.compute_zonemd(zone, size_limit=100000) == digest
    # An exceeded budget raises rather than returning a partial digest.
    with pytest.raises(dns.zone.DigestBudgetExceeded):
        dns.zonemd.compute_zonemd(zone, size_limit=1)
    dns.zonemd.compute_zonemd(zone, attach=True)
    statuses = dns.zonemd.verify_zonemd(zone, size_limit=1)
    assert diagnostics(statuses) == [dns.zonemd.ZonemdDiagnostic.BUDGET_EXCEEDED]


def test_zonemd_and_its_rrsig_excluded():
    zone = make_zone()
    digest = dns.zonemd.compute_zonemd(zone)
    # An RRSIG covering the apex ZONEMD RRset is excluded from the digest.
    add_rrsig(zone, "example.", "ZONEMD")
    assert dns.zonemd.compute_zonemd(zone) == digest
    # An RRSIG covering another RRset is digested.
    add_rrsig(zone, "ns1.example.", "A")
    assert dns.zonemd.compute_zonemd(zone) != digest
