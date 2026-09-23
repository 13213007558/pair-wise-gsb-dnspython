# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for offline NSEC denial-of-existence validation."""

import pytest

import dns.dnssec
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.zone
from cryptography.hazmat.primitives.asymmetric import ed25519
from dns.rdtypes.ANY.RRSIG import RRSIG

IN = dns.rdataclass.IN
NSEC = dns.rdatatype.NSEC
RRSIG_TYPE = dns.rdatatype.RRSIG

EXAMPLE_ZONE_TEXT = """
example. 3600 IN SOA ns1.example. admin.example. 1 3600 600 86400 3600
example. 3600 IN NS ns1.example.
ns1.example. 3600 IN A 192.0.2.1
a.example. 3600 IN A 192.0.2.2
c.example. 3600 IN A 192.0.2.3
cname.example. 3600 IN CNAME a.example.
sub.example. 3600 IN NS ns1.other.example.
"""

WILDCARD_ZONE_TEXT = """
example. 3600 IN SOA ns1.example. admin.example. 1 3600 600 86400 3600
example. 3600 IN NS ns1.example.
*.example. 3600 IN A 192.0.2.10
a.example. 3600 IN A 192.0.2.2
"""

OTHER_ZONE_TEXT = """
otherzone. 3600 IN SOA ns1.otherzone. admin.otherzone. 1 3600 600 86400 3600
otherzone. 3600 IN NS ns1.otherzone.
ns1.otherzone. 3600 IN A 192.0.2.1
zzz.otherzone. 3600 IN A 192.0.2.2
"""


def make_signed_zone(zone_text, origin):
    zone = dns.zone.from_text(zone_text, origin, relativize=False)
    private_key = ed25519.Ed25519PrivateKey.generate()
    dnskey = dns.dnssec.make_dnskey(
        private_key.public_key(), dns.dnssec.Algorithm.ED25519
    )
    with zone.writer() as txn:
        dns.dnssec.sign_zone(zone, txn=txn, keys=[(private_key, dnskey)], lifetime=3600)
    return zone


@pytest.fixture(scope="module")
def example_zone():
    return make_signed_zone(EXAMPLE_ZONE_TEXT, "example.")


@pytest.fixture(scope="module")
def wildcard_zone():
    return make_signed_zone(WILDCARD_ZONE_TEXT, "example.")


@pytest.fixture(scope="module")
def other_zone():
    return make_signed_zone(OTHER_ZONE_TEXT, "otherzone.")


def keys_for(zone):
    return {zone.origin: zone[zone.origin].get_rdataset(IN, dns.rdatatype.DNSKEY)}


def get_rrset(zone, name, rdtype, covers=dns.rdatatype.NONE):
    name = dns.name.from_text(name)
    rdataset = zone[name].get_rdataset(IN, rdtype, covers)
    assert rdataset is not None
    return dns.rrset.from_rdata(name, rdataset.ttl, *rdataset)


def nsec_authority(zone, *names):
    rrsets = []
    for name in names:
        rrsets.append(get_rrset(zone, name, NSEC))
        rrsets.append(get_rrset(zone, name, RRSIG_TYPE, NSEC))
    return rrsets


def make_response(qname, qtype, rcode, authority=(), answer=()):
    query = dns.message.make_query(qname, qtype)
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    response.answer.extend(answer)
    response.authority.extend(authority)
    return response


def validate(response, keys, **kwargs):
    return dns.dnssec.validate_denial_of_existence(
        response.question[0], response, keys, **kwargs
    )


def nsec_owners(result):
    return {rrset.name for rrset in result.rrsets if rrset.rdtype == NSEC}


def test_nxdomain_valid(example_zone):
    keys = keys_for(example_zone)
    response = make_response(
        "b.example.",
        "A",
        dns.rcode.NXDOMAIN,
        nsec_authority(example_zone, "a.example.", "example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.VALID
    # The proving NSECs and their RRSIGs are reported.
    assert nsec_owners(result) == {
        dns.name.from_text("a.example."),
        dns.name.from_text("example."),
    }
    assert len(result.rrsets) == 4


def test_nxdomain_valid_wrap_around(example_zone):
    # y.example. is only covered by the last NSEC of the zone, whose
    # interval wraps around to the zone apex.
    keys = keys_for(example_zone)
    response = make_response(
        "y.example.",
        "A",
        dns.rcode.NXDOMAIN,
        nsec_authority(example_zone, "sub.example.", "example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.VALID


def test_nxdomain_wildcard_not_excluded(example_zone):
    # Proving the qname does not exist is not enough; the matching
    # wildcard must be excluded too.
    keys = keys_for(example_zone)
    response = make_response(
        "b.example.",
        "A",
        dns.rcode.NXDOMAIN,
        nsec_authority(example_zone, "a.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def test_nxdomain_valid_signatures_but_uncovered_interval(example_zone):
    # The signatures are perfectly valid, but no NSEC interval covers the
    # qname, so the denial proof must fail even though the cryptographic
    # validation succeeds.
    keys = keys_for(example_zone)
    authority = nsec_authority(example_zone, "c.example.", "example.")
    response = make_response("b.example.", "A", dns.rcode.NXDOMAIN, authority)
    for i in range(0, len(authority), 2):
        nsec_rrset, rrsig_rrset = authority[i], authority[i + 1]
        # Cryptographic validation of each NSEC passes.
        dns.dnssec.validate(nsec_rrset, rrsig_rrset, keys)
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def test_nxdomain_wildcard_exists(wildcard_zone):
    keys = keys_for(wildcard_zone)
    response = make_response(
        "b.example.",
        "A",
        dns.rcode.NXDOMAIN,
        nsec_authority(wildcard_zone, "a.example.", "*.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.BOGUS


def test_nxdomain_qname_exists(example_zone):
    keys = keys_for(example_zone)
    response = make_response(
        "a.example.",
        "A",
        dns.rcode.NXDOMAIN,
        nsec_authority(example_zone, "a.example.", "example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.BOGUS


def test_nxdomain_below_delegation(example_zone):
    # x.sub.example. is below a delegation and thus out of the zone; the
    # zone's NSECs cannot prove anything about it.
    keys = keys_for(example_zone)
    response = make_response(
        "x.sub.example.",
        "A",
        dns.rcode.NXDOMAIN,
        nsec_authority(example_zone, "sub.example.", "example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def test_nodata_valid(example_zone):
    keys = keys_for(example_zone)
    response = make_response(
        "a.example.",
        "TXT",
        dns.rcode.NOERROR,
        nsec_authority(example_zone, "a.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.VALID
    assert nsec_owners(result) == {dns.name.from_text("a.example.")}


def test_nodata_type_exists(example_zone):
    keys = keys_for(example_zone)
    response = make_response(
        "a.example.",
        "A",
        dns.rcode.NOERROR,
        nsec_authority(example_zone, "a.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.BOGUS


def test_nodata_cname(example_zone):
    # RFC 6840 section 4.1: an NSEC with the CNAME bit set does not prove
    # the nonexistence of any other type.
    keys = keys_for(example_zone)
    response = make_response(
        "cname.example.",
        "TXT",
        dns.rcode.NOERROR,
        nsec_authority(example_zone, "cname.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.BOGUS


def test_nodata_ds_insecure_delegation(example_zone):
    keys = keys_for(example_zone)
    response = make_response(
        "sub.example.",
        "DS",
        dns.rcode.NOERROR,
        nsec_authority(example_zone, "sub.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.VALID


def test_nodata_at_delegation_other_type(example_zone):
    keys = keys_for(example_zone)
    response = make_response(
        "sub.example.",
        "A",
        dns.rcode.NOERROR,
        nsec_authority(example_zone, "sub.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def test_nodata_no_matching_nsec(example_zone):
    keys = keys_for(example_zone)
    response = make_response(
        "b.example.",
        "TXT",
        dns.rcode.NOERROR,
        nsec_authority(example_zone, "a.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def test_qname_out_of_zone(example_zone):
    keys = keys_for(example_zone)
    response = make_response(
        "www.other.",
        "A",
        dns.rcode.NXDOMAIN,
        nsec_authority(example_zone, "a.example.", "example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def test_nsec_from_other_zone(example_zone, other_zone):
    # The other zone's wrap-around NSEC happens to cover the qname and is
    # validly signed by the other zone's (trusted) key, but it cannot
    # prove anything about this zone.
    keys = keys_for(example_zone)
    keys.update(keys_for(other_zone))
    other_nsec = get_rrset(other_zone, "zzz.otherzone.", NSEC)
    other_rrsig = get_rrset(other_zone, "zzz.otherzone.", RRSIG_TYPE, NSEC)
    # The other zone's NSEC is cryptographically valid ...
    dns.dnssec.validate(other_nsec, other_rrsig, keys_for(other_zone))
    # ... and its interval covers the qname ...
    assert dns.dnssec._nsec_covers(
        other_nsec.name, other_nsec[0].next, dns.name.from_text("b.example.")
    )
    # ... but it is not usable for a proof about example.
    response = make_response(
        "b.example.", "A", dns.rcode.NXDOMAIN, [other_nsec, other_rrsig]
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def corrupt_rrsig(rrset):
    corrupted = []
    for rrsig in rrset:
        signature = bytearray(rrsig.signature)
        signature[-1] ^= 0xFF
        corrupted.append(
            RRSIG(
                IN,
                RRSIG_TYPE,
                rrsig.type_covered,
                rrsig.algorithm,
                rrsig.labels,
                rrsig.original_ttl,
                rrsig.expiration,
                rrsig.inception,
                rrsig.key_tag,
                rrsig.signer,
                bytes(signature),
            )
        )
    return dns.rrset.from_rdata(rrset.name, rrset.ttl, *corrupted)


def test_bad_signature(example_zone):
    keys = keys_for(example_zone)
    authority = nsec_authority(example_zone, "a.example.", "example.")
    authority[1] = corrupt_rrsig(authority[1])
    response = make_response("b.example.", "A", dns.rcode.NXDOMAIN, authority)
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.BOGUS


def test_expired_signature(example_zone):
    keys = keys_for(example_zone)
    authority = nsec_authority(example_zone, "a.example.", "example.")
    response = make_response("b.example.", "A", dns.rcode.NXDOMAIN, authority)
    expiration = authority[1][0].expiration
    result = validate(response, keys, now=expiration + 10)
    assert result.result == dns.dnssec.DenialOfExistence.BOGUS


def test_unknown_key(example_zone):
    private_key = ed25519.Ed25519PrivateKey.generate()
    wrong_dnskey = dns.dnssec.make_dnskey(
        private_key.public_key(), dns.dnssec.Algorithm.ED25519
    )
    keys = {example_zone.origin: dns.rdataset.from_rdata(3600, wrong_dnskey)}
    response = make_response(
        "b.example.",
        "A",
        dns.rcode.NXDOMAIN,
        nsec_authority(example_zone, "a.example.", "example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.BOGUS


def test_not_a_negative_response(example_zone):
    keys = keys_for(example_zone)
    answer = [get_rrset(example_zone, "a.example.", dns.rdatatype.A)]
    response = make_response(
        "a.example.",
        "A",
        dns.rcode.NOERROR,
        nsec_authority(example_zone, "a.example."),
        answer,
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT

    response = make_response(
        "b.example.",
        "A",
        dns.rcode.SERVFAIL,
        nsec_authority(example_zone, "a.example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def test_missing_rrsig(example_zone):
    keys = keys_for(example_zone)
    # An NSEC without any RRSIG from the zone cannot be validated.
    authority = [get_rrset(example_zone, "a.example.", NSEC)]
    response = make_response("b.example.", "A", dns.rcode.NXDOMAIN, authority)
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.BOGUS


def test_nodata_ds_at_apex(example_zone):
    # DS records live in the parent zone; the child zone's apex NSEC
    # cannot prove their nonexistence.
    keys = keys_for(example_zone)
    response = make_response(
        "example.",
        "DS",
        dns.rcode.NOERROR,
        nsec_authority(example_zone, "example."),
    )
    result = validate(response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.INSUFFICIENT


def test_question_forms(example_zone):
    keys = keys_for(example_zone)
    authority = nsec_authority(example_zone, "a.example.", "example.")
    response = make_response("b.example.", "A", dns.rcode.NXDOMAIN, authority)
    # A (name, rdatatype) tuple.
    result = dns.dnssec.validate_denial_of_existence(
        (dns.name.from_text("b.example."), dns.rdatatype.A), response, keys
    )
    assert result.result == dns.dnssec.DenialOfExistence.VALID
    # A query message.
    query = dns.message.make_query("b.example.", "A")
    result = dns.dnssec.validate_denial_of_existence(query, response, keys)
    assert result.result == dns.dnssec.DenialOfExistence.VALID
