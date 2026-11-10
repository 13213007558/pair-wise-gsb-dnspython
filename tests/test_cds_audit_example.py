# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for examples/cds_audit: offline CDS/CDNSKEY parent-side review."""

from datetime import datetime, timedelta, UTC

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.dnssectypes import Algorithm, DSDigest
from dns.rdtypes.ANY.CDNSKEY import CDNSKEY
from dns.rdtypes.ANY.CDS import CDS
from dns.rdtypes.dnskeybase import Flag

from examples.cds_audit.auditor import (
    AcceptancePolicy,
    AuditInput,
    RejectReason,
    ReviewStatus,
    audit_cds,
    audit_zone_text,
)

pytestmark = pytest.mark.skipif(
    not dns._features.have("dnssec"), reason="DNSSEC support not available"
)

ZONE = dns.name.from_text("lab.example.")
NOW = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)


class Key:
    def __init__(self):
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.dnskey = dns.dnssec.make_dnskey(
            self.private.public_key(),
            Algorithm.ED25519,
            flags=Flag.ZONE | Flag.SEP,
        )

    @property
    def tag(self):
        return self.dnskey.key_id()

    def sign(self, rdtype, rdata, *, inception=None, expiration=None):
        rrset = dns.rrset.RRset(ZONE, dns.rdataclass.IN, rdtype)
        for record in rdata:
            rrset.add(record, 3600)
        return dns.dnssec.sign(
            rrset,
            self.private,
            ZONE,
            self.dnskey,
            inception=inception or NOW - timedelta(hours=1),
            expiration=expiration or NOW + timedelta(days=7),
        )


@pytest.fixture
def keys():
    return Key(), Key(), Key()


def make_cds(key):
    return dns.dnssec.make_cds(ZONE, key, DSDigest.SHA256)


def make_cds_any_digest(key, digest_type):
    """Build a CDS for any digest type, bypassing the default RFC 9904 policy."""
    ds = dns.dnssec.make_ds(ZONE, key, digest_type, policy=dns.dnssec.allow_all_policy)
    return CDS(
        ds.rdclass,
        dns.rdatatype.CDS,
        ds.key_tag,
        ds.algorithm,
        ds.digest_type,
        ds.digest,
    )


def make_cdnskey(key):
    return CDNSKEY(
        key.rdclass,
        dns.rdatatype.CDNSKEY,
        key.flags,
        key.protocol,
        key.algorithm,
        key.key,
    )


def make_ds(key):
    return dns.dnssec.make_ds(ZONE, key, DSDigest.SHA256)


def bundle(current, dnskeys, **kw):
    return AuditInput(
        zone_name=ZONE,
        current_ds=current,
        dnskeys=dnskeys,
        cds=kw.get("cds"),
        cdnskey=kw.get("cdnskey"),
        cds_signatures=kw.get("cds_sigs", ()),
        cdnskey_signatures=kw.get("cdnskey_sigs", ()),
    )


def test_trusted_rollover_is_accepted(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(cds,),
            cds_sigs=(old.sign(dns.rdatatype.CDS, (cds,)),),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.ACCEPTED
    assert [ds.key_tag for ds in result.add] == [new.tag]
    assert [ds.key_tag for ds in result.remove] == [old.tag]
    assert result.signature_evidence[0].signer_matches_trusted_ds


def test_self_authorized_key_is_rejected(keys):
    old, _, stranger = keys
    cds = make_cds(stranger.dnskey)
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, stranger.dnskey),
            cds=(cds,),
            cds_sigs=(stranger.sign(dns.rdatatype.CDS, (cds,)),),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.REJECTED
    assert RejectReason.NO_CONTINUITY in result.reasons
    assert result.accepted_changes() == ()


def test_expired_signature_is_rejected(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    sig = old.sign(
        dns.rdatatype.CDS,
        (cds,),
        inception=NOW - timedelta(days=30),
        expiration=NOW - timedelta(seconds=1),
    )
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(cds,),
            cds_sigs=(sig,),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.REJECTED
    assert RejectReason.EXPIRED_SIGNATURE in result.reasons


def test_not_yet_valid_signature_is_rejected(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    sig = old.sign(
        dns.rdatatype.CDS,
        (cds,),
        inception=NOW + timedelta(days=1),
        expiration=NOW + timedelta(days=8),
    )
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(cds,),
            cds_sigs=(sig,),
        ),
        NOW,
    )
    assert RejectReason.NOT_YET_VALID_SIGNATURE in result.reasons


def test_unsigned_proposal_is_rejected(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(cds,),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.REJECTED
    assert RejectReason.UNSIGNED_PROPOSAL in result.reasons


def test_inconsistent_cds_and_cdnskey(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    cdnskey = make_cdnskey(old.dnskey)
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(cds,),
            cdnskey=(cdnskey,),
            cds_sigs=(old.sign(dns.rdatatype.CDS, (cds,)),),
            cdnskey_sigs=(old.sign(dns.rdatatype.CDNSKEY, (cdnskey,)),),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.REJECTED
    assert RejectReason.INCONSISTENT_PROPOSAL in result.reasons


def test_consistent_cds_and_cdnskey_is_accepted(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    cdnskey = make_cdnskey(new.dnskey)
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(cds,),
            cdnskey=(cdnskey,),
            cds_sigs=(old.sign(dns.rdatatype.CDS, (cds,)),),
            cdnskey_sigs=(old.sign(dns.rdatatype.CDNSKEY, (cdnskey,)),),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.ACCEPTED
    assert [ds.key_tag for ds in result.add] == [new.tag]


def test_cds_delete_signal_requires_confirmation(keys):
    old, _, _ = keys
    wipe = CDS(dns.rdataclass.IN, dns.rdatatype.CDS, 0, 0, 0, b"\x00")
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey,),
            cds=(wipe,),
            cds_sigs=(old.sign(dns.rdatatype.CDS, (wipe,)),),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.DELETION_PENDING_CONFIRMATION
    assert result.remove == (make_ds(old.dnskey),) or len(result.remove) == 1
    assert result.add == ()
    assert result.accepted_changes() == ()


def test_cdnskey_delete_signal_requires_confirmation(keys):
    old, _, _ = keys
    wipe = CDNSKEY(dns.rdataclass.IN, dns.rdatatype.CDNSKEY, 0, 0, 0, b"")
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey,),
            cdnskey=(wipe,),
            cdnskey_sigs=(old.sign(dns.rdatatype.CDNSKEY, (wipe,)),),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.DELETION_PENDING_CONFIRMATION
    assert result.deletion_requested


def test_unsigned_delete_signal_is_rejected(keys):
    old, _, _ = keys
    wipe = CDS(dns.rdataclass.IN, dns.rdatatype.CDS, 0, 0, 0, b"\x00")
    result = audit_cds(
        bundle((make_ds(old.dnskey),), (old.dnskey,), cds=(wipe,)),
        NOW,
    )
    assert result.status is ReviewStatus.REJECTED
    assert RejectReason.UNSIGNED_PROPOSAL in result.reasons


def test_mixed_delete_marker_is_invalid(keys):
    old, new, _ = keys
    wipe = CDS(dns.rdataclass.IN, dns.rdatatype.CDS, 0, 0, 0, b"\x00")
    cds = (wipe, make_cds(new.dnskey))
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=cds,
            cds_sigs=(old.sign(dns.rdatatype.CDS, cds),),
        ),
        NOW,
    )
    assert RejectReason.INVALID_DELETE_SIGNAL in result.reasons


def test_sha1_digest_rejected_by_default_policy(keys):
    old, new, _ = keys
    sha1_cds = make_cds_any_digest(new.dnskey, DSDigest.SHA1)
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(sha1_cds,),
            cds_sigs=(old.sign(dns.rdatatype.CDS, (sha1_cds,)),),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.REJECTED
    assert RejectReason.UNSUPPORTED_DIGEST_ALGORITHM in result.reasons


def test_policy_can_widen_digest_range(keys):
    old, new, _ = keys
    sha1_cds = make_cds_any_digest(new.dnskey, DSDigest.SHA1)
    policy = AcceptancePolicy(
        accepted_digest_algorithms=frozenset(
            {DSDigest.SHA1, DSDigest.SHA256, DSDigest.SHA384}
        )
    )
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(sha1_cds,),
            cds_sigs=(old.sign(dns.rdatatype.CDS, (sha1_cds,)),),
        ),
        NOW,
        policy,
    )
    assert result.status is ReviewStatus.ACCEPTED


def test_missing_material_and_no_proposal(keys):
    old, _, _ = keys
    no_keys = audit_cds(bundle((make_ds(old.dnskey),), ()), NOW)
    assert no_keys.reasons == (RejectReason.MISSING_MATERIAL,)
    no_proposal = audit_cds(bundle((make_ds(old.dnskey),), (old.dnskey,)), NOW)
    assert no_proposal.reasons == (RejectReason.NO_PROPOSAL,)


def test_no_trust_anchor_when_ds_matches_no_dnskey(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (new.dnskey,),
            cds=(cds,),
            cds_sigs=(new.sign(dns.rdatatype.CDS, (cds,)),),
        ),
        NOW,
    )
    assert RejectReason.NO_TRUST_ANCHOR in result.reasons
    assert result.status is ReviewStatus.REJECTED


def test_two_stage_rollover(keys):
    old, new, _ = keys
    stage_a = (make_cds(old.dnskey), make_cds(new.dnskey))
    first = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=stage_a,
            cds_sigs=(old.sign(dns.rdatatype.CDS, stage_a),),
        ),
        NOW,
    )
    assert first.status is ReviewStatus.ACCEPTED
    assert [ds.key_tag for ds in first.keep] == [old.tag]
    stage_b = make_cds(new.dnskey)
    second = audit_cds(
        bundle(
            (make_ds(old.dnskey), make_ds(new.dnskey)),
            (old.dnskey, new.dnskey),
            cds=(stage_b,),
            cds_sigs=(new.sign(dns.rdatatype.CDS, (stage_b,)),),
        ),
        NOW,
    )
    assert second.status is ReviewStatus.ACCEPTED
    assert [ds.key_tag for ds in second.keep] == [new.tag]
    assert [ds.key_tag for ds in second.remove] == [old.tag]


def test_audit_zone_text_roundtrip(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    sig = old.sign(dns.rdatatype.CDS, (cds,))
    text = "\n".join(
        [
            "id 1",
            "opcode QUERY",
            "rcode NOERROR",
            "flags QR",
            ";QUESTION",
            ";ANSWER",
            "lab.example. 3600 IN DS " + make_ds(old.dnskey).to_text(),
            "lab.example. 3600 IN DNSKEY " + old.dnskey.to_text(),
            "lab.example. 3600 IN DNSKEY " + new.dnskey.to_text(),
            "lab.example. 3600 IN CDS " + cds.to_text(),
            "lab.example. 3600 IN RRSIG " + sig.to_text(),
            ";AUTHORITY",
            ";ADDITIONAL",
        ]
    )
    result = audit_zone_text(text, NOW)
    assert result.status is ReviewStatus.ACCEPTED
    assert [ds.key_tag for ds in result.add] == [new.tag]


def test_one_valid_trusted_sig_survives_an_expired_one(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    good = old.sign(dns.rdatatype.CDS, (cds,))
    stale = old.sign(
        dns.rdatatype.CDS,
        (cds,),
        inception=NOW - timedelta(days=30),
        expiration=NOW - timedelta(days=1),
    )
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (old.dnskey, new.dnskey),
            cds=(cds,),
            cds_sigs=(stale, good),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.ACCEPTED
    assert len(result.signature_evidence) == 2
    assert {ev.accepted for ev in result.signature_evidence} == {True, False}
    assert any(
        ev.accepted and ev.signer_matches_trusted_ds for ev in result.signature_evidence
    )


def test_unknown_signer_keytag_is_rejected(keys):
    old, new, _ = keys
    cds = make_cds(new.dnskey)
    sig = old.sign(dns.rdatatype.CDS, (cds,))
    # Present only the new key, so the old key signing the set is "unknown".
    result = audit_cds(
        bundle(
            (make_ds(old.dnskey),),
            (new.dnskey,),
            cds=(cds,),
            cds_sigs=(sig,),
        ),
        NOW,
    )
    assert result.status is ReviewStatus.REJECTED
    assert RejectReason.NO_TRUST_ANCHOR in result.reasons
    assert RejectReason.UNTRUSTED_SIGNATURE in result.reasons
