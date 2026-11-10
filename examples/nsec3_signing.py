#!/usr/bin/env python3

# Offline NSEC3 zone signing with dns.dnssec.sign_zone (RFC 5155).
#
# The example zone contains every interesting name class:
#   - the zone apex and ordinary names
#   - an empty non-terminal chain ("ent" / "deep.ent")
#   - a wildcard ("*.wild")
#   - a signed delegation (NS + DS) and an unsigned delegation (NS only)
#
# The same zone is signed twice, once without Opt-Out and once with it, so
# the difference Opt-Out makes to the NSEC3 chain is directly visible:
# with Opt-Out the unsigned delegation point is omitted from the chain
# entirely, while the DS-bearing delegation stays in both chains.

import base64

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.zone
from dns.rdtypes.ANY.NSEC3PARAM import NSEC3PARAM
from dns.rdtypes.dnskeybase import Flag

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError as exc:  # pragma: no cover
    raise SystemExit("This example requires the 'cryptography' package") from exc

zone_text = """
example. 3600 IN SOA foo.example. bar.example. 1 2 3 4 5
example. 3600 IN NS ns1.example.
ns1.example. 3600 IN A 10.0.0.1
a.deep.ent.example. 3600 IN TXT foo
*.wild.example. 3600 IN A 10.0.0.10
signed-deleg.example. 3600 IN NS nsx.example.
signed-deleg.example. 3600 IN DS 12345 13 2 0100D208742A23024DF3C8827DFF3EB3E25126E9B72850E99D6055E18913CB2F
unsigned-deleg.example. 3600 IN NS nsy.example.
child.unsigned-deleg.example. 3600 IN A 10.0.0.20
"""

SALT = bytes.fromhex("aabbccdd")
ITERATIONS = 5


def make_keys():
    ksk_private = ed25519.Ed25519PrivateKey.generate()
    ksk = dns.dnssec.make_dnskey(
        ksk_private.public_key(),
        dns.dnssec.Algorithm.ED25519,
        flags=Flag.ZONE | Flag.SEP,
    )
    zsk_private = ed25519.Ed25519PrivateKey.generate()
    zsk = dns.dnssec.make_dnskey(
        zsk_private.public_key(), dns.dnssec.Algorithm.ED25519, flags=Flag.ZONE
    )
    return [(ksk_private, ksk), (zsk_private, zsk)]


def bitmap_text(nsec3_rdata):
    types = set()
    for window, bitmap in nsec3_rdata.windows:
        for octet_index, octet in enumerate(bitmap):
            for bit in range(8):
                if octet & (0x80 >> bit):
                    types.add(window * 256 + octet_index * 8 + bit)
    return " ".join(sorted(dns.rdatatype.to_text(t) for t in types))


def sign(optout):
    zone = dns.zone.from_text(zone_text, "example.")
    parameters = NSEC3PARAM(
        dns.rdataclass.IN,
        dns.rdatatype.NSEC3PARAM,
        dns.dnssec.NSEC3Hash.SHA1,
        0,
        ITERATIONS,
        SALT,
    )
    with zone.writer() as txn:
        dns.dnssec.sign_zone(
            zone,
            txn=txn,
            keys=make_keys(),
            lifetime=3600,
            nsec3=parameters,
            nsec3_optout=optout,
        )
    return zone


def main():
    for optout in (False, True):
        banner = "WITH Opt-Out" if optout else "without Opt-Out"
        print(f"=== NSEC3 chain {banner} ===")
        zone = sign(optout)
        records = sorted(
            zone.iterate_rdatasets("NSEC3"),
            key=lambda item: item[0].relativize(zone.origin).labels[0],
        )
        for name, rdataset in records:
            rdata = rdataset[0]
            owner = name.relativize(zone.origin).labels[0].decode()
            nxt = base64.b32hexencode(rdata.next).decode().rstrip("=")
            print(f"  {owner}  next={nxt}  types: {bitmap_text(rdata)}")
        unsigned_hash = dns.dnssec.nsec3_hash(
            "unsigned-deleg.example.", SALT, ITERATIONS, 1
        )
        present = any(
            name.relativize(zone.origin).labels[0].decode() == unsigned_hash
            for name, _ in records
        )
        print(
            "  unsigned delegation 'unsigned-deleg.example.' is "
            + ("IN the chain" if present else "OMITTED from the chain")
        )
        print()


if __name__ == "__main__":
    main()
