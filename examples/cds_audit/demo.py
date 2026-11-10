"""Local-key demonstration of the offline CDS/CDNSKEY reviewer.

All keys are generated in-process with cryptography and every signature is
created locally; nothing is ever sent to a registrar or queried over the
network.  A single fixed validation instant is used for every review so the
output is reproducible.

Scenarios:
  1. Safe key roll-over, authenticated by the currently trusted KSK.
  2. A new key that signs its own proposal (no chain of trust) -> rejected.
  3. An expired RRSIG -> rejected with an explicit time-based reason.
  4. CDS and CDNSKEY disagree -> rejected as inconsistent.
  5. RFC 8078 delete signal -> separate state awaiting human confirmation.
  6. Two-stage roll-over: add the new KSK first, retire the old one only
     after the parent's trust has advanced.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, UTC

from cryptography.hazmat.primitives.asymmetric import ed25519

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
from dns.dnssectypes import Algorithm, DSDigest
from dns.rdtypes.ANY.CDNSKEY import CDNSKEY
from dns.rdtypes.ANY.CDS import CDS
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.RRSIG import RRSIG
from dns.rdtypes.dnskeybase import Flag

from examples.cds_audit.auditor import (
    AcceptancePolicy,
    AuditInput,
    ReviewStatus,
    audit_cds,
)

ZONE = dns.name.from_text("demo.example.")
VALIDATION_TIME = datetime(2026, 11, 10, 12, 0, 0, tzinfo=UTC)
SIG_TTL = 3600


@dataclass
class LocalKey:
    private: ed25519.Ed25519PrivateKey
    dnskey: DNSKEY

    @property
    def tag(self) -> int:
        return self.dnskey.key_id()


def make_ksk() -> LocalKey:
    private = ed25519.Ed25519PrivateKey.generate()
    dnskey = dns.dnssec.make_dnskey(
        private.public_key(),
        Algorithm.ED25519,
        flags=Flag.ZONE | Flag.SEP,
    )
    return LocalKey(private, dnskey)


def ds_for(key: DNSKEY, digest: DSDigest = DSDigest.SHA256) -> DS:
    return dns.dnssec.make_ds(ZONE, key, digest)


def cds_for(key: DNSKEY, digest: DSDigest = DSDigest.SHA256) -> CDS:
    return dns.dnssec.make_cds(ZONE, key, digest)


def cdnskey_for(key: DNSKEY) -> CDNSKEY:
    return CDNSKEY(
        rdclass=key.rdclass,
        rdtype=dns.rdatatype.CDNSKEY,
        flags=key.flags,
        protocol=key.protocol,
        algorithm=key.algorithm,
        key=key.key,
    )


def delete_cds() -> CDS:
    # RFC 8078 delete CDS: key tag/algorithm/digest type 0 and one zero byte.
    return CDS(dns.rdataclass.IN, dns.rdatatype.CDS, 0, 0, 0, b"\x00")


def delete_cdnskey() -> CDNSKEY:
    return CDNSKEY(dns.rdataclass.IN, dns.rdatatype.CDNSKEY, 0, 0, 0, b"")


def sign(
    key: LocalKey,
    rdtype: dns.rdatatype.RdataType,
    rdata: tuple,
    *,
    inception: datetime | None = None,
    expiration: datetime | None = None,
) -> RRSIG:
    inception = inception or (VALIDATION_TIME - timedelta(hours=1))
    expiration = expiration or (VALIDATION_TIME + timedelta(days=14))
    rrset = dns.rrset.RRset(ZONE, dns.rdataclass.IN, rdtype)
    for record in rdata:
        rrset.add(record, SIG_TTL)
    return dns.dnssec.sign(
        rrset,
        key.private,
        ZONE,
        key.dnskey,
        inception=inception,
        expiration=expiration,
    )


def review(
    title: str,
    *,
    current_ds: tuple[DS, ...],
    dnskeys: tuple[DNSKEY, ...],
    cds: tuple[CDS, ...] | None = None,
    cdnskey: tuple[CDNSKEY, ...] | None = None,
    cds_sigs: tuple[RRSIG, ...] = (),
    cdnskey_sigs: tuple[RRSIG, ...] = (),
    policy: AcceptancePolicy | None = None,
):
    result = audit_cds(
        AuditInput(
            zone_name=ZONE,
            current_ds=current_ds,
            dnskeys=dnskeys,
            cds=cds,
            cdnskey=cdnskey,
            cds_signatures=cds_sigs,
            cdnskey_signatures=cdnskey_sigs,
        ),
        VALIDATION_TIME,
        policy,
    )
    print("=" * 72)
    print(title)
    print("-" * 72)
    print(f"结论: {result.status.value}")
    print(f"说明: {result.detail}")
    if result.reasons:
        print("原因代码: " + ", ".join(reason.value for reason in result.reasons))
    print(f"当前受信 key tag: {list(result.trusted_keytags)}")
    print(f"拟保留 DS: {[ds.key_tag for ds in result.keep]}")
    print(f"拟新增 DS: {[ds.key_tag for ds in result.add]}")
    print(f"拟删除 DS: {[ds.key_tag for ds in result.remove]}")
    for ev in result.signature_evidence:
        state = "通过" if ev.accepted else f"失败({ev.failure})"
        print(
            f"  签名证据 {ev.rrtype}: key tag {ev.signer_keytag} "
            f"({ev.signer_algorithm}), 命中现有DS={ev.signer_matches_trusted_ds}, "
            f"{state}, 有效期 {ev.inception:%Y-%m-%d %H:%M} ~ "
            f"{ev.expiration:%Y-%m-%d %H:%M}"
        )
    print()
    return result


def main() -> None:
    old_ksk = make_ksk()
    new_ksk = make_ksk()
    stranger = make_ksk()

    old_ds = ds_for(old_ksk.dnskey)
    new_ds = ds_for(new_ksk.dnskey)

    # 1. Safe roll-over: the trusted old KSK signs a CDS naming the new KSK.
    rollover_cds = cds_for(new_ksk.dnskey)
    result = review(
        "场景 1: 安全换钥 — 受信旧 KSK 对新 KSK 的 CDS 签名",
        current_ds=(old_ds,),
        dnskeys=(old_ksk.dnskey, new_ksk.dnskey),
        cds=(rollover_cds,),
        cds_sigs=(sign(old_ksk, dns.rdatatype.CDS, (rollover_cds,)),),
    )
    assert result.status is ReviewStatus.ACCEPTED
    assert [ds.key_tag for ds in result.add] == [new_ksk.tag]
    assert [ds.key_tag for ds in result.remove] == [old_ksk.tag]
    assert result.signature_evidence[0].signer_matches_trusted_ds

    # 2. Self-authorized new key: the stranger signs its own CDS.
    rogue_cds = cds_for(stranger.dnskey)
    result = review(
        "场景 2: 未获授权 — 新钥匙给自己的 CDS 签名",
        current_ds=(old_ds,),
        dnskeys=(old_ksk.dnskey, stranger.dnskey),
        cds=(rogue_cds,),
        cds_sigs=(sign(stranger, dns.rdatatype.CDS, (rogue_cds,)),),
    )
    assert result.status is ReviewStatus.REJECTED
    # The diff is shown for the operator, but nothing is applicable.
    assert result.accepted_changes() == ()

    # 3. Expired signature on an otherwise valid roll-over proposal.
    expired_sig = sign(
        old_ksk,
        dns.rdatatype.CDS,
        (rollover_cds,),
        inception=VALIDATION_TIME - timedelta(days=30),
        expiration=VALIDATION_TIME - timedelta(days=1),
    )
    result = review(
        "场景 3: 签名已过期 — 固定审查时间下必须拒绝",
        current_ds=(old_ds,),
        dnskeys=(old_ksk.dnskey, new_ksk.dnskey),
        cds=(rollover_cds,),
        cds_sigs=(expired_sig,),
    )
    assert result.status is ReviewStatus.REJECTED

    # 4. CDS and CDNSKEY present but describing different keys.
    cds_part = cds_for(new_ksk.dnskey)
    cdnskey_part = cdnskey_for(old_ksk.dnskey)
    result = review(
        "场景 4: CDS 与 CDNSKEY 含义不一致",
        current_ds=(old_ds,),
        dnskeys=(old_ksk.dnskey, new_ksk.dnskey),
        cds=(cds_part,),
        cdnskey=(cdnskey_part,),
        cds_sigs=(sign(old_ksk, dns.rdatatype.CDS, (cds_part,)),),
        cdnskey_sigs=(sign(old_ksk, dns.rdatatype.CDNSKEY, (cdnskey_part,)),),
    )
    assert result.status is ReviewStatus.REJECTED

    # 5. RFC 8078 delete signal, properly signed by the trusted KSK.
    wipe = delete_cds()
    result = review(
        "场景 5: 删除信号 — 进入人工确认状态而非直接清空 DS",
        current_ds=(old_ds,),
        dnskeys=(old_ksk.dnskey,),
        cds=(wipe,),
        cds_sigs=(sign(old_ksk, dns.rdatatype.CDS, (wipe,)),),
    )
    assert result.status is ReviewStatus.DELETION_PENDING_CONFIRMATION
    assert result.remove == (old_ds,)
    assert result.accepted_changes() == ()

    # 5b. The same intent expressed as an all-zero CDNSKEY delete signal.
    wipe_key = delete_cdnskey()
    result = review(
        "场景 5b: CDNSKEY 删除信号 — 同样进入人工确认状态",
        current_ds=(old_ds,),
        dnskeys=(old_ksk.dnskey,),
        cdnskey=(wipe_key,),
        cdnskey_sigs=(sign(old_ksk, dns.rdatatype.CDNSKEY, (wipe_key,)),),
    )
    assert result.status is ReviewStatus.DELETION_PENDING_CONFIRMATION
    assert result.deletion_requested

    # 6. Two-stage roll-over. Stage A adds the new KSK while retaining trust.
    stage_a_cds = (cds_for(old_ksk.dnskey), cds_for(new_ksk.dnskey))
    result = review(
        "场景 6a: 两阶段换钥 — 先引入新 KSK 并保留旧 KSK",
        current_ds=(old_ds,),
        dnskeys=(old_ksk.dnskey, new_ksk.dnskey),
        cds=stage_a_cds,
        cds_sigs=(sign(old_ksk, dns.rdatatype.CDS, stage_a_cds),),
    )
    assert result.status is ReviewStatus.ACCEPTED
    assert [ds.key_tag for ds in result.keep] == [old_ksk.tag]
    assert [ds.key_tag for ds in result.add] == [new_ksk.tag]

    # Stage B runs once the parent actually publishes both DS records: the
    # new KSK now has its own DS anchor and can authenticate retiring the old.
    stage_b_cds = cds_for(new_ksk.dnskey)
    result = review(
        "场景 6b: 两阶段换钥 — 信任推进后由新 KSK 移除旧 DS",
        current_ds=(old_ds, new_ds),
        dnskeys=(old_ksk.dnskey, new_ksk.dnskey),
        cds=(stage_b_cds,),
        cds_sigs=(sign(new_ksk, dns.rdatatype.CDS, (stage_b_cds,)),),
    )
    assert result.status is ReviewStatus.ACCEPTED
    assert [ds.key_tag for ds in result.keep] == [new_ksk.tag]
    assert [ds.key_tag for ds in result.remove] == [old_ksk.tag]

    print("全部场景断言通过；本程序仅输出离线审查结果，未联系任何注册商。")


if __name__ == "__main__":
    main()
