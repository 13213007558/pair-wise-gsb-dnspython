"""Offline review of child-zone CDS/CDNSKEY proposals against parent trust.

This module implements the parent-side review described in RFC 7344 and
RFC 8078 without ever contacting a registrar: given the DS records currently
trusted by the parent, the child zone's DNSKEY RRset, and the child's
proposed CDS and/or CDNSKEY records together with their RRSIGs, it decides
which DS changes (if any) are safe to apply.

Trust can only advance from the keys already covered by the parent's DS
records: a brand-new key cannot authorize its own adoption merely by signing
the proposal.  A valid delete signal (RFC 8078 section 4) is never treated as
an ordinary "apply the empty set" change; it is returned in a separate state
that requires explicit human confirmation.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from datetime import datetime, UTC

import dns.dnssec
import dns.message
import dns.name
import dns.node
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
from dns.dnssectypes import Algorithm, DSDigest
from dns.exception import DNSException
from dns.rdtypes.ANY.CDNSKEY import CDNSKEY
from dns.rdtypes.ANY.CDS import CDS
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.RRSIG import RRSIG

# RFC 8078 section 4 (with Errata ID 5049): the delete signal is a single
# CDS/CDNSKEY RR whose rdata is all zeros.  The CDS form carries one zero
# digest byte because digest type 0 still requires a length-1 digest field.
DELETE_KEY_TAG = 0
DELETE_ALGORITHM = 0
DELETE_DIGEST_TYPE = 0
DELETE_CDS_DIGEST = b"\x00"


class RejectReason(enum.Enum):
    """Machine-readable reasons a proposal cannot be accepted."""

    MISSING_MATERIAL = "missing-material"
    NO_PROPOSAL = "no-proposal"
    NO_TRUST_ANCHOR = "no-trust-anchor"
    UNSIGNED_PROPOSAL = "unsigned-proposal"
    UNTRUSTED_SIGNATURE = "untrusted-signature"
    EXPIRED_SIGNATURE = "expired-signature"
    NOT_YET_VALID_SIGNATURE = "not-yet-valid-signature"
    SIGNATURE_VERIFY_FAILED = "signature-verify-failed"
    INCONSISTENT_PROPOSAL = "inconsistent-cds-cdnskey"
    INVALID_DELETE_SIGNAL = "invalid-delete-signal"
    UNSUPPORTED_KEY_ALGORITHM = "unsupported-key-algorithm"
    UNSUPPORTED_DIGEST_ALGORITHM = "unsupported-digest-algorithm"
    PROPOSED_DS_WITHOUT_DNSKEY = "proposed-ds-without-dnskey"
    NO_CONTINUITY = "no-trust-continuity"
    INVALID_INPUT = "invalid-input"


class ReviewStatus(enum.Enum):
    """Overall disposition of a reviewed proposal."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"
    DELETION_PENDING_CONFIRMATION = "deletion-pending-confirmation"


@dataclass(frozen=True)
class AcceptancePolicy:
    """Algorithms/digests the parent is willing to accept in new DS records.

    The defaults follow the conservative recommendations of RFC 8624/9904:
    SHA-1 DS digests and the deprecated DSA/RSA-MD5 key algorithms are not
    accepted.  Everything is overridable so a deployment can widen or narrow
    the range.
    """

    accepted_key_algorithms: frozenset[Algorithm] = frozenset(
        {
            Algorithm.RSASHA256,
            Algorithm.RSASHA512,
            Algorithm.ECDSAP256SHA256,
            Algorithm.ECDSAP384SHA384,
            Algorithm.ED25519,
            Algorithm.ED448,
        }
    )
    accepted_digest_algorithms: frozenset[DSDigest] = frozenset(
        {DSDigest.SHA256, DSDigest.SHA384}
    )

    def key_algorithm_accepted(self, algorithm: int) -> bool:
        return Algorithm.make(algorithm) in self.accepted_key_algorithms

    def digest_algorithm_accepted(self, digest_type: int) -> bool:
        return DSDigest.make(digest_type) in self.accepted_digest_algorithms


@dataclass(frozen=True)
class AuditInput:
    """Everything the offline reviewer needs for one child zone.

    :param zone_name: The child zone apex (the owner name of the proposal).
    :param current_ds: DS records currently published/trusted at the parent.
    :param dnskeys: The child zone's full DNSKEY RRset.
    :param cds: Proposed CDS records, or ``None`` if absent.
    :param cdnskey: Proposed CDNSKEY records, or ``None`` if absent.
    :param cds_signatures: RRSIG RRs covering the CDS RRset.
    :param cdnskey_signatures: RRSIG RRs covering the CDNSKEY RRset.
    """

    zone_name: dns.name.Name
    current_ds: tuple[DS, ...]
    dnskeys: tuple[DNSKEY, ...]
    cds: tuple[CDS, ...] | None
    cdnskey: tuple[CDNSKEY, ...] | None
    cds_signatures: tuple[RRSIG, ...] = ()
    cdnskey_signatures: tuple[RRSIG, ...] = ()


@dataclass(frozen=True)
class SignatureEvidence:
    """What established (or failed to establish) the authenticity of a set."""

    rrtype: str
    signer_keytag: int
    signer_algorithm: str
    signer_matches_trusted_ds: bool
    inception: datetime
    expiration: datetime
    accepted: bool
    failure: str | None = None


@dataclass(frozen=True)
class ReviewResult:
    """The complete review outcome.

    :param status: Overall disposition.
    :param reasons: Rejection reason codes (empty when accepted).
    :param keep: DS records already trusted that remain in the proposal.
    :param add: New DS records the parent may publish.
    :param remove: Trusted DS records the proposal withdraws.
    :param deletion_requested: Whether a valid RFC 8078 delete signal was seen.
    :param signature_evidence: Per-RRSIG verification evidence.
    :param trusted_keytags: Key tags covered by the current DS records.
    :param detail: Human-readable explanation, in English.
    """

    status: ReviewStatus
    reasons: tuple[RejectReason, ...]
    keep: tuple[DS, ...]
    add: tuple[DS, ...]
    remove: tuple[DS, ...]
    deletion_requested: bool
    signature_evidence: tuple[SignatureEvidence, ...]
    trusted_keytags: tuple[int, ...]
    detail: str

    def accepted_changes(self) -> tuple[DS, ...]:
        """The DS RRs that may actually be added (empty unless accepted)."""
        if self.status is ReviewStatus.ACCEPTED:
            return self.add
        return ()


# Internal permissive DNSSEC policy: make_ds() must be able to compute any
# digest so the reviewer can compare material; AcceptancePolicy decides
# separately whether that digest is acceptable to this parent.
_COMPUTE_POLICY = dns.dnssec.allow_all_policy


def _posix_utc(value: float | datetime) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    return datetime.fromtimestamp(value, tz=UTC)


def _ds_wire_tuple(ds: DS) -> tuple[int, int, int, bytes]:
    return (ds.key_tag, int(ds.algorithm), int(ds.digest_type), bytes(ds.digest))


def _is_delete_cds(rr: CDS) -> bool:
    return (
        rr.key_tag == DELETE_KEY_TAG
        and int(rr.algorithm) == DELETE_ALGORITHM
        and int(rr.digest_type) == DELETE_DIGEST_TYPE
        and bytes(rr.digest) == DELETE_CDS_DIGEST
    )


def _is_delete_cdnskey(rr: CDNSKEY) -> bool:
    return (
        int(rr.flags) == 0
        and rr.protocol == 0
        and int(rr.algorithm) == DELETE_ALGORITHM
        and bytes(rr.key) == b""
    )


def _dnskey_to_ds_set(
    name: dns.name.Name, keys: tuple[CDNSKEY, ...], digests: frozenset[DSDigest]
) -> tuple[DS, ...]:
    result: set[tuple[int, int, int, bytes]] = set()
    out: list[DS] = []
    for key in keys:
        for digest_type in digests:
            ds = dns.dnssec.make_ds(name, key, digest_type, policy=_COMPUTE_POLICY)
            token = _ds_wire_tuple(ds)
            if token not in result:
                result.add(token)
                out.append(ds)
    return tuple(out)


def _cds_to_ds(records: tuple[CDS, ...]) -> tuple[DS, ...]:
    out: list[DS] = []
    seen: set[tuple[int, int, int, bytes]] = set()
    for record in records:
        ds = DS(
            rdclass=record.rdclass,
            rdtype=dns.rdatatype.DS,
            key_tag=record.key_tag,
            algorithm=record.algorithm,
            digest_type=record.digest_type,
            digest=record.digest,
        )
        token = _ds_wire_tuple(ds)
        if token not in seen:
            seen.add(token)
            out.append(ds)
    return tuple(out)


def _trusted_keys(
    name: dns.name.Name,
    dnskeys: tuple[DNSKEY, ...],
    current_ds: tuple[DS, ...],
) -> tuple[set[DNSKEY], set[int]]:
    """DNSKEYs actually vouched for by a current parent DS, and their tags."""
    trusted: set[DNSKEY] = set()
    trusted_tags: set[int] = set()
    for key in dnskeys:
        for anchor in current_ds:
            if int(anchor.algorithm) != int(key.algorithm):
                continue
            try:
                candidate = dns.dnssec.make_ds(
                    name,
                    key,
                    DSDigest.make(int(anchor.digest_type)),
                    policy=_COMPUTE_POLICY,
                )
            except DNSException:
                continue
            if _ds_wire_tuple(candidate) == _ds_wire_tuple(anchor):
                trusted.add(key)
                trusted_tags.add(key.key_id())
                break
    return trusted, trusted_tags


def _as_rrset(
    name: dns.name.Name, rdtype: dns.rdatatype.RdataType, rdata: tuple
) -> dns.rrset.RRset:
    rrset = dns.rrset.RRset(name, dns.rdataclass.IN, rdtype)
    for record in rdata:
        rrset.add(record)
    return rrset


def _verify_signatures(
    name: dns.name.Name,
    rdtype: dns.rdatatype.RdataType,
    rdata: tuple,
    signatures: tuple[RRSIG, ...],
    dnskeys: tuple[DNSKEY, ...],
    trusted: set[DNSKEY],
    now: float,
) -> tuple[list[SignatureEvidence], list[RejectReason]]:
    """Verify all RRSIGs over one proposal set at the fixed validation time."""
    label = dns.rdatatype.to_text(rdtype)
    evidence: list[SignatureEvidence] = []
    reasons: list[RejectReason] = []
    if not signatures:
        return evidence, [RejectReason.UNSIGNED_PROPOSAL]

    key_node = dns.node.Node()
    key_rdataset = dns.rdataset.Rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    for key in dnskeys:
        key_rdataset.add(key)
    key_node.rdatasets.append(key_rdataset)
    keys: dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset] = {name: key_node}
    rrset = _as_rrset(name, rdtype, rdata)

    any_valid = False
    any_trusted = False
    raw_failures: list[RejectReason] = []
    for sig in signatures:
        tag = int(sig.key_tag)
        signer_key = next((key for key in dnskeys if key.key_id() == tag), None)
        matches_trusted = signer_key in trusted
        failure: str | None = None
        reason: RejectReason | None = None
        if signer_key is None:
            failure = "no DNSKEY with the RRSIG key tag is present"
            reason = RejectReason.UNTRUSTED_SIGNATURE
        else:
            try:
                dns.dnssec.validate_rrsig(rrset, sig, keys, now=now)
            except DNSException as exc:
                failure = str(exc)
                text = (failure or "").lower()
                if "expired" in text:
                    reason = RejectReason.EXPIRED_SIGNATURE
                elif "not yet valid" in text:
                    reason = RejectReason.NOT_YET_VALID_SIGNATURE
                else:
                    reason = RejectReason.SIGNATURE_VERIFY_FAILED
        accepted = failure is None
        if accepted:
            any_valid = True
            if matches_trusted:
                any_trusted = True
        elif reason is not None and reason not in raw_failures:
            raw_failures.append(reason)
        evidence.append(
            SignatureEvidence(
                rrtype=label,
                signer_keytag=tag,
                signer_algorithm=Algorithm.to_text(sig.algorithm),
                signer_matches_trusted_ds=matches_trusted,
                inception=_posix_utc(sig.inception),
                expiration=_posix_utc(sig.expiration),
                accepted=accepted,
                failure=failure,
            )
        )

    if any_trusted:
        # A currently trusted key validates the set; failures on other
        # signatures are evidence only, not reasons to reject.
        return evidence, reasons
    if any_valid:
        # The cryptography verifies, but every signing key is outside the
        # parent's current DS trust: self-authorization is not authorization.
        reasons.append(RejectReason.NO_CONTINUITY)
    else:
        reasons.extend(raw_failures)
        if not reasons:
            reasons.append(RejectReason.SIGNATURE_VERIFY_FAILED)
    return evidence, reasons


def _check_algorithm_support(
    proposed: tuple[DS, ...],
    dnskeys: tuple[DNSKEY, ...],
    policy: AcceptancePolicy,
) -> list[RejectReason]:
    reasons: list[RejectReason] = []
    keys_by_tag = {key.key_id(): key for key in dnskeys}
    for ds in proposed:
        if not policy.digest_algorithm_accepted(int(ds.digest_type)):
            reasons.append(RejectReason.UNSUPPORTED_DIGEST_ALGORITHM)
        key = keys_by_tag.get(ds.key_tag)
        if key is None or not policy.key_algorithm_accepted(int(key.algorithm)):
            reasons.append(RejectReason.UNSUPPORTED_KEY_ALGORITHM)
    return reasons


def _proposed_ds_from_cds(records: tuple[CDS, ...]) -> tuple[DS, ...] | None:
    """Interpret a CDS set, returning ``()`` for a valid RFC 8078 delete."""
    if len(records) == 1 and _is_delete_cds(records[0]):
        return ()
    if any(_is_delete_cds(record) for record in records):
        return None
    return _cds_to_ds(records)


def _proposed_ds_from_cdnskey(
    name: dns.name.Name,
    records: tuple[CDNSKEY, ...],
    digests: frozenset[DSDigest],
) -> tuple[DS, ...] | None:
    """Interpret a CDNSKEY set, returning ``()`` for a valid delete."""
    if len(records) == 1 and _is_delete_cdnskey(records[0]):
        return ()
    if any(_is_delete_cdnskey(record) for record in records):
        return None
    try:
        return _dnskey_to_ds_set(name, records, digests)
    except DNSException:
        return None


def audit_cds(
    data: AuditInput,
    validation_time: float | datetime,
    policy: AcceptancePolicy | None = None,
) -> ReviewResult:
    """Review a CDS/CDNSKEY proposal and return the acceptable DS changes.

    :param data: The offline audit bundle (trust anchors, keys, proposal).
    :param validation_time: Fixed "now" used for RRSIG validity checks, so
        reviews are deterministic and reproducible.
    :param policy: Accepted algorithm/digest range; conservative defaults when
        ``None``.
    """
    if policy is None:
        policy = AcceptancePolicy()
    now = (
        validation_time.timestamp()
        if isinstance(validation_time, datetime)
        else float(validation_time)
    )

    reasons: list[RejectReason] = []
    evidence: list[SignatureEvidence] = []
    empty: tuple[DS, ...] = ()

    # --- 1. Material completeness ---------------------------------------
    if not isinstance(data.zone_name, dns.name.Name):
        return _reject(
            [RejectReason.INVALID_INPUT],
            empty,
            empty,
            empty,
            evidence,
            (),
            "zone name is missing or not a dns.name.Name",
        )
    if not data.dnskeys:
        return _reject(
            [RejectReason.MISSING_MATERIAL],
            empty,
            empty,
            empty,
            evidence,
            (),
            "the child DNSKEY RRset is required to evaluate a proposal",
        )
    if data.cds is None and data.cdnskey is None:
        return _reject(
            [RejectReason.NO_PROPOSAL],
            empty,
            empty,
            empty,
            evidence,
            (),
            "neither a CDS nor a CDNSKEY RRset was provided",
        )

    trusted, trusted_tags = _trusted_keys(data.zone_name, data.dnskeys, data.current_ds)
    if not trusted:
        reasons.append(RejectReason.NO_TRUST_ANCHOR)

    # --- 2. Decode the proposal on each present side ---------------------
    cds_ds: tuple[DS, ...] | None = None
    cdnskey_ds: tuple[DS, ...] | None = None
    if data.cds is not None:
        cds_ds = _proposed_ds_from_cds(data.cds)
        if cds_ds is None:
            reasons.append(RejectReason.INVALID_DELETE_SIGNAL)
        ev, sig_reasons = _verify_signatures(
            data.zone_name,
            dns.rdatatype.CDS,
            data.cds,
            data.cds_signatures,
            data.dnskeys,
            trusted,
            now,
        )
        evidence.extend(ev)
        reasons.extend(r for r in sig_reasons if r not in reasons)
    if data.cdnskey is not None:
        cdnskey_ds = _proposed_ds_from_cdnskey(
            data.zone_name, data.cdnskey, policy.accepted_digest_algorithms
        )
        if cdnskey_ds is None:
            reasons.append(RejectReason.INVALID_DELETE_SIGNAL)
        ev, sig_reasons = _verify_signatures(
            data.zone_name,
            dns.rdatatype.CDNSKEY,
            data.cdnskey,
            data.cdnskey_signatures,
            data.dnskeys,
            trusted,
            now,
        )
        evidence.extend(ev)
        reasons.extend(r for r in sig_reasons if r not in reasons)

    deletion_requested = cds_ds == () or cdnskey_ds == ()

    # --- 3. CDS and CDNSKEY must mean the same thing when both appear ----
    # RFC 7344 section 4.2: with both types, every CDS must be a DS
    # derivable from the CDNSKEY set using the digest types the CDS names.
    if cds_ds is not None and cdnskey_ds is not None:
        if deletion_requested:
            consistent = cds_ds == () and cdnskey_ds == ()
        else:
            digest_types = frozenset(
                DSDigest.make(int(ds.digest_type)) for ds in cds_ds
            )
            derived = _dnskey_to_ds_set(
                data.zone_name, data.cdnskey or (), digest_types
            )
            consistent = {_ds_wire_tuple(ds) for ds in cds_ds} == {
                _ds_wire_tuple(ds) for ds in derived
            }
        if not consistent:
            reasons.append(RejectReason.INCONSISTENT_PROPOSAL)
    # Prefer the explicit CDS-derived set; otherwise use the CDNSKEY one.
    proposed = cds_ds if cds_ds is not None else (cdnskey_ds or empty)

    # --- 4. Every proposed DS must correspond to a present DNSKEY, and the
    # algorithm/digest range must be acceptable to this parent.
    key_index: dict[tuple[int, int], DNSKEY] = {
        (key.key_id(), int(key.algorithm)): key for key in data.dnskeys
    }
    for ds in proposed:
        if (ds.key_tag, int(ds.algorithm)) not in key_index:
            reasons.append(RejectReason.PROPOSED_DS_WITHOUT_DNSKEY)
    reasons.extend(
        reason
        for reason in _check_algorithm_support(proposed, data.dnskeys, policy)
        if reason not in reasons
    )

    current_tokens = {_ds_wire_tuple(ds): ds for ds in data.current_ds}
    proposed_tokens = {_ds_wire_tuple(ds): ds for ds in proposed}
    keep = tuple(
        current_tokens[token] for token in current_tokens if token in proposed_tokens
    )
    add = tuple(
        proposed_tokens[token]
        for token in proposed_tokens
        if token not in current_tokens
    )
    remove = tuple(
        current_tokens[token]
        for token in current_tokens
        if token not in proposed_tokens
    )

    # --- 5. A valid delete signal is a separate, human-gated state -------
    if deletion_requested and not reasons:
        return ReviewResult(
            status=ReviewStatus.DELETION_PENDING_CONFIRMATION,
            reasons=(),
            keep=empty,
            add=empty,
            remove=data.current_ds,
            deletion_requested=True,
            signature_evidence=tuple(evidence),
            trusted_keytags=tuple(sorted(trusted_tags)),
            detail=(
                "the child requests removal of all DS records (RFC 8078 "
                "delete signal); the request is properly signed by a trusted "
                "key but must not be applied without explicit human "
                "confirmation"
            ),
        )

    if reasons:
        return _reject(
            reasons,
            keep,
            add,
            remove,
            evidence,
            tuple(sorted(trusted_tags)),
            _explain_rejections(reasons),
        )

    # --- 6. Continuity is established by a valid signature from a key the
    # parent currently trusts (see _verify_signatures), not by requiring an
    # old DS to survive: RFC 7344 allows a fully trusted key to roll the
    # whole DS set in one authenticated step. A new key signing its own
    # proposal never meets that bar and was already rejected above.
    return ReviewResult(
        status=ReviewStatus.ACCEPTED,
        reasons=(),
        keep=keep,
        add=add,
        remove=remove,
        deletion_requested=False,
        signature_evidence=tuple(evidence),
        trusted_keytags=tuple(sorted(trusted_tags)),
        detail=(
            f"proposal authenticated by trusted key tag(s) "
            f"{', '.join(str(tag) for tag in sorted(trusted_tags))}; "
            f"{len(add)} DS record(s) to add, {len(keep)} to keep, "
            f"{len(remove)} to remove"
        ),
    )


def _reject(
    reasons: list[RejectReason],
    keep: tuple[DS, ...],
    add: tuple[DS, ...],
    remove: tuple[DS, ...],
    evidence: list[SignatureEvidence],
    trusted_keytags: tuple[int, ...],
    detail: str,
) -> ReviewResult:
    return ReviewResult(
        status=ReviewStatus.REJECTED,
        reasons=tuple(reasons),
        keep=keep,
        add=add,
        remove=remove,
        deletion_requested=False,
        signature_evidence=tuple(evidence),
        trusted_keytags=trusted_keytags,
        detail=detail,
    )


def _explain_rejections(reasons: list[RejectReason]) -> str:
    return "rejected: " + "; ".join(reason.value for reason in reasons)


def audit_zone_text(
    zone_text: str,
    validation_time: float | datetime,
    policy: AcceptancePolicy | None = None,
) -> ReviewResult:
    """Review a proposal supplied as a master-file-style text fragment.

    The fragment holds the apex ``DS`` (current parent trust), ``DNSKEY`` and
    at least one of ``CDS`` / ``CDNSKEY``, plus the covering ``RRSIG``
    records.  Parsing is done with the DNS message reader so no SOA/NS
    scaffolding is required; it is purely offline and performs no queries.
    """
    message = dns.message.from_text(zone_text)
    by_type: dict[dns.rdatatype.RdataType, list] = {}
    for rrset in message.answer:
        by_type.setdefault(rrset.rdtype, []).extend(rrset)

    def rdatas(rdtype: dns.rdatatype.RdataType) -> tuple:
        return tuple(by_type.get(rdtype, ()))

    def signatures(covered: dns.rdatatype.RdataType) -> tuple[RRSIG, ...]:
        return tuple(
            rdata
            for rdata in by_type.get(dns.rdatatype.RRSIG, ())
            if rdata.type_covered == covered
        )

    owners = {rrset.name for rrset in message.answer}
    if len(owners) != 1:
        raise ValueError("all records in the fragment must share one owner")
    apex = owners.pop()

    ds_records = rdatas(dns.rdatatype.DS)
    dnskey_records = rdatas(dns.rdatatype.DNSKEY)
    cds_records = rdatas(dns.rdatatype.CDS)
    cdnskey_records = rdatas(dns.rdatatype.CDNSKEY)

    data = AuditInput(
        zone_name=apex,
        current_ds=tuple(ds_records),
        dnskeys=tuple(dnskey_records),
        cds=tuple(cds_records) if cds_records else None,
        cdnskey=tuple(cdnskey_records) if cdnskey_records else None,
        cds_signatures=signatures(dns.rdatatype.CDS),
        cdnskey_signatures=signatures(dns.rdatatype.CDNSKEY),
    )
    return audit_cds(data, validation_time, policy)
