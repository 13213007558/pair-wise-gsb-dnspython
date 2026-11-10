# Offline CDS/CDNSKEY parent-side review

`auditor.py` reviews child-zone CDS/CDNSKEY proposals (RFC 7344) against the
DS records a parent currently trusts, entirely offline: it never queries the
DNS and never contacts a registrar. It only produces a review result that a
separate, human-operated workflow could act on.

## Trust rules

- Trust only advances from keys covered by the parent's current DS records.
  A new key that signs its own CDS/CDNSKEY is not authorized: the signature
  may validate cryptographically, but it fails the continuity check.
- RRSIGs are validated at a caller-supplied fixed instant, so expired or
  not-yet-valid signatures are reported deterministically with an explicit
  reason code.
- When both CDS and CDNSKEY are present, the DS set derived from the CDNSKEY
  (using the digest types named by the CDS) must match the CDS exactly.
- Accepted key algorithms and DS digest types are controlled by
  `AcceptancePolicy`; the default rejects SHA-1 digests and obsolete key
  algorithms per RFC 8624/9904.
- An RFC 8078 delete signal (CDS `0 0 0 00`, or an all-zero CDNSKEY) is not
  applied as an ordinary empty update. A properly signed signal returns
  `ReviewStatus.DELETION_PENDING_CONFIRMATION` and waits for explicit human
  confirmation.

## Result

Each `ReviewResult` reports the DS records to keep, add and remove, the
machine-readable rejection reasons (if any), and per-signature evidence
including which signer matched a current parent DS.

## Demo and tests

```
python3 -m examples.cds_audit.demo
pytest tests/test_cds_audit_example.py
```

The demo generates local Ed25519 keys and walks through a trusted key
roll-over, a self-authorized (rejected) key, an expired signature, an
inconsistent CDS/CDNSKEY pair, a delete signal awaiting confirmation, and a
two-stage roll-over where trust advances one key at a time.
