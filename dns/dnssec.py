# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Copyright (C) 2003-2017 Nominum, Inc.
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose with or without fee is hereby granted,
# provided that the above copyright notice and this permission notice
# appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NOMINUM DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NOMINUM BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
# OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""Common DNSSEC-related functions and constants."""

# pylint: disable=unused-import

import base64
import contextlib
import dataclasses
import functools
import hashlib
import math
import struct
import time
from collections.abc import Callable, Iterable
from datetime import datetime
from enum import Enum
from typing import Union, cast

import dns._features
import dns.message
import dns.name
import dns.node
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.serial
import dns.transaction
import dns.zone
from dns.dnssectypes import Algorithm, DSDigest, NSEC3Hash
from dns.exception import AlgorithmKeyMismatch as AlgorithmKeyMismatch
from dns.exception import DeniedByPolicy, UnsupportedAlgorithm, ValidationFailure
from dns.exception import IncompleteProof as IncompleteProof
from dns.exception import NSEC3Unsupported as NSEC3Unsupported
from dns.rdtypes.ANY.CDNSKEY import CDNSKEY
from dns.rdtypes.ANY.CDS import CDS
from dns.rdtypes.ANY.DNSKEY import DNSKEY
from dns.rdtypes.ANY.DS import DS
from dns.rdtypes.ANY.NSEC import NSEC, Bitmap
from dns.rdtypes.ANY.NSEC3PARAM import NSEC3PARAM
from dns.rdtypes.ANY.RRSIG import RRSIG, sigtime_to_posixtime
from dns.rdtypes.dnskeybase import Flag

PublicKey = Union[
    "GenericPublicKey",
    "rsa.RSAPublicKey",
    "ec.EllipticCurvePublicKey",
    "ed25519.Ed25519PublicKey",
    "ed448.Ed448PublicKey",
    "mldsa.MLDSA44PublicKey",
]

PrivateKey = Union[
    "GenericPrivateKey",
    "rsa.RSAPrivateKey",
    "ec.EllipticCurvePrivateKey",
    "ed25519.Ed25519PrivateKey",
    "ed448.Ed448PrivateKey",
    "mldsa.MLDSA44PrivateKey",
]

RRsetSigner = Callable[[dns.transaction.Transaction, dns.rrset.RRset], None]


def algorithm_from_text(text: str) -> Algorithm:
    """Convert text into a DNSSEC algorithm value.

    :param text: The text to convert into an algorithm value.
    :type text: str
    :rtype: int
    """

    return Algorithm.from_text(text)


def algorithm_to_text(value: Algorithm | int) -> str:
    """Convert a DNSSEC algorithm value to text

    :param value: The algorithm value.
    :type value: :py:class:`dns.dnssectypes.Algorithm`
    :rtype: str
    """

    return Algorithm.to_text(value)


def to_timestamp(value: datetime | str | float | int) -> int:
    """Convert various format to a timestamp"""
    if isinstance(value, datetime):
        return int(value.timestamp())
    elif isinstance(value, str):
        return sigtime_to_posixtime(value)
    elif isinstance(value, float):
        return int(value)
    elif isinstance(value, int):
        return value
    else:
        raise TypeError("Unsupported timestamp type")


def key_id(key: DNSKEY | CDNSKEY) -> int:
    """Return the key id (a 16-bit number) for the specified key.

    :param key: The DNSKEY or CDNSKEY rdata.
    :type key: :py:class:`dns.rdtypes.ANY.DNSKEY.DNSKEY`
    :rtype: int
    """

    return key.key_id()


class Policy:
    def __init__(self):
        pass

    def ok_to_sign(self, key: DNSKEY) -> bool:  # pragma: no cover
        return False

    def ok_to_validate(self, key: DNSKEY) -> bool:  # pragma: no cover
        return False

    def ok_to_create_ds(self, algorithm: DSDigest) -> bool:  # pragma: no cover
        return False

    def ok_to_validate_ds(self, algorithm: DSDigest) -> bool:  # pragma: no cover
        return False


class SimpleDeny(Policy):
    def __init__(self, deny_sign, deny_validate, deny_create_ds, deny_validate_ds):
        super().__init__()
        self._deny_sign = deny_sign
        self._deny_validate = deny_validate
        self._deny_create_ds = deny_create_ds
        self._deny_validate_ds = deny_validate_ds

    def ok_to_sign(self, key: DNSKEY) -> bool:
        return key.algorithm not in self._deny_sign

    def ok_to_validate(self, key: DNSKEY) -> bool:
        return key.algorithm not in self._deny_validate

    def ok_to_create_ds(self, algorithm: DSDigest) -> bool:
        return algorithm not in self._deny_create_ds

    def ok_to_validate_ds(self, algorithm: DSDigest) -> bool:
        return algorithm not in self._deny_validate_ds


rfc_8624_policy = SimpleDeny(
    {Algorithm.RSAMD5, Algorithm.DSA, Algorithm.DSANSEC3SHA1, Algorithm.ECCGOST},
    {Algorithm.RSAMD5, Algorithm.DSA, Algorithm.DSANSEC3SHA1},
    {DSDigest.NULL, DSDigest.SHA1, DSDigest.GOST},
    {DSDigest.NULL},
)

rfc_9904_policy = rfc_8624_policy

allow_all_policy = SimpleDeny(set(), set(), set(), set())


default_policy = rfc_9904_policy


def make_ds(
    name: dns.name.Name | str,
    key: dns.rdata.Rdata,
    algorithm: DSDigest | str,
    origin: dns.name.Name | None = None,
    policy: Policy | None = None,
    validating: bool = False,
) -> DS:
    """Create a DS record for a DNSSEC key.

    :param name: The owner name of the DS record.
    :type name: :py:class:`dns.name.Name` or str
    :param key: The key the DS is about.
    :type key: :py:class:`dns.rdtypes.ANY.DNSKEY.DNSKEY` or
        :py:class:`dns.rdtypes.ANY.CDNSKEY.CDNSKEY`
    :param algorithm: The hash algorithm. Currently supported: ``"SHA1"``,
        ``"SHA256"``, ``"SHA384"`` (case-insensitive).
    :type algorithm: str or int
    :param origin: If *key* is a relative name, it will be made absolute
        using this origin.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :param policy: The policy to use. If ``None``, ``dns.dnssec.default_policy``
        is used (defaults to RFC 9904 policy).
    :type policy: :py:class:`dns.dnssec.Policy` or ``None``
    :param validating: If ``True``, policy is checked in validating mode ("Is it
        ok to validate using this digest algorithm?"). Otherwise checked in
        creating mode.
    :type validating: bool
    :raises UnsupportedAlgorithm: If the algorithm is unknown.
    :raises DeniedByPolicy: If the algorithm is denied by policy.
    :rtype: :py:class:`dns.rdtypes.ANY.DS.DS`
    """

    if policy is None:
        policy = default_policy
    try:
        if isinstance(algorithm, str):
            algorithm = DSDigest[algorithm.upper()]
    except Exception:
        raise UnsupportedAlgorithm(f'unsupported algorithm "{algorithm}"')
    if validating:
        check = policy.ok_to_validate_ds
    else:
        check = policy.ok_to_create_ds
    if not check(algorithm):
        raise DeniedByPolicy
    if not isinstance(key, DNSKEY | CDNSKEY):
        raise ValueError("key is not a DNSKEY | CDNSKEY")
    if algorithm == DSDigest.SHA1:
        dshash = hashlib.sha1()
    elif algorithm == DSDigest.SHA256:
        dshash = hashlib.sha256()
    elif algorithm == DSDigest.SHA384:
        dshash = hashlib.sha384()
    else:
        raise UnsupportedAlgorithm(f'unsupported algorithm "{algorithm}"')

    if isinstance(name, str):
        name = dns.name.from_text(name, origin)
    wire = name.canonicalize().to_wire()
    kwire = key.to_wire(origin=origin)
    assert wire is not None and kwire is not None  # for mypy
    dshash.update(wire)
    dshash.update(kwire)
    digest = dshash.digest()

    dsrdata = struct.pack("!HBB", key_id(key), key.algorithm, algorithm) + digest
    ds = dns.rdata.from_wire(
        dns.rdataclass.IN, dns.rdatatype.DS, dsrdata, 0, len(dsrdata)
    )
    return cast(DS, ds)


def make_cds(
    name: dns.name.Name | str,
    key: dns.rdata.Rdata,
    algorithm: DSDigest | str,
    origin: dns.name.Name | None = None,
) -> CDS:
    """Create a CDS record for a DNSSEC key.

    :param name: The owner name of the DS record.
    :type name: :py:class:`dns.name.Name` or str
    :param key: The key the DS is about.
    :type key: :py:class:`dns.rdtypes.ANY.DNSKEY.DNSKEY` or
        :py:class:`dns.rdtypes.ANY.CDNSKEY.CDNSKEY`
    :param algorithm: The hash algorithm. Currently supported: ``"SHA1"``,
        ``"SHA256"``, ``"SHA384"`` (case-insensitive).
    :type algorithm: str or int
    :param origin: If *key* is a relative name, it will be made absolute
        using this origin.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :raises UnsupportedAlgorithm: If the algorithm is unknown.
    :rtype: :py:class:`dns.rdtypes.ANY.CDS.CDS`
    """

    ds = make_ds(name, key, algorithm, origin)
    return CDS(
        rdclass=ds.rdclass,
        rdtype=dns.rdatatype.CDS,
        key_tag=ds.key_tag,
        algorithm=ds.algorithm,
        digest_type=ds.digest_type,
        digest=ds.digest,
    )


def _find_candidate_keys(
    keys: dict[dns.name.Name, dns.rdataset.Rdataset | dns.node.Node], rrsig: RRSIG
) -> list[DNSKEY] | None:
    value = keys.get(rrsig.signer)
    if isinstance(value, dns.node.Node):
        rdataset = value.get_rdataset(dns.rdataclass.IN, dns.rdatatype.DNSKEY)
    else:
        rdataset = value
    if rdataset is None:
        return None
    return [
        cast(DNSKEY, rd)
        for rd in rdataset
        if rd.algorithm == rrsig.algorithm
        and key_id(rd) == rrsig.key_tag
        and (rd.flags & Flag.ZONE) == Flag.ZONE  # RFC 4034 2.1.1
        and rd.protocol == 3  # RFC 4034 2.1.2
        # A revoked key may only validate the DNSKEY RRset (RFC 5011 2.1)
        and (
            (rd.flags & Flag.REVOKE) == 0 or rrsig.type_covered == dns.rdatatype.DNSKEY
        )
    ]


def _get_rrname_rdataset(
    rrset: dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset],
) -> tuple[dns.name.Name, dns.rdataset.Rdataset]:
    if isinstance(rrset, tuple):
        return rrset[0], rrset[1]
    else:
        return rrset.name, rrset


def _validate_signature(sig: bytes, data: bytes, key: DNSKEY) -> None:
    # pylint: disable=possibly-used-before-assignment
    public_cls = get_algorithm_cls_from_dnskey(key).public_cls
    try:
        public_key = public_cls.from_dnskey(key)
    except ValueError:
        raise ValidationFailure("invalid public key")
    public_key.verify(sig, data)


def _validate_rrsig(
    rrset: dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset],
    rrsig: RRSIG,
    keys: dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset],
    origin: dns.name.Name | None = None,
    now: float | None = None,
    policy: Policy | None = None,
) -> None:
    """Validate an RRset against a single signature rdata, throwing an
    exception if validation is not successful.

    *rrset*, the RRset to validate.  This can be a
    ``dns.rrset.RRset`` or a (``dns.name.Name``, ``dns.rdataset.Rdataset``)
    tuple.

    :param rrsig: The signature to validate.
    :type rrsig: :py:class:`dns.rdata.Rdata`
    :param keys: The key dictionary, keyed by :py:class:`dns.name.Name`, with
        :py:class:`dns.node.Node` or :py:class:`dns.rdataset.Rdataset` values.
    :param origin: The origin to use for relative names.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :param now: The current time in seconds since the epoch. If ``None``,
        the actual current time is used.
    :type now: float or ``None``
    :param policy: The policy to use. If ``None``, ``dns.dnssec.default_policy``
        is used (defaults to RFC 9904 policy).
    :type policy: :py:class:`dns.dnssec.Policy` or ``None``
    :raises ValidationFailure: If the signature is expired, not yet valid, the
        public key is invalid, the algorithm is unknown, verification fails, etc.
    :raises UnsupportedAlgorithm: If the algorithm is recognized but not
        implemented.
    """

    if policy is None:
        policy = default_policy

    # RFC 4035 section 5.3.1: the RRSIG must cover the RRset's type and class.
    _, rdataset = _get_rrname_rdataset(rrset)
    if rrsig.type_covered != rdataset.rdtype or rrsig.rdclass != rdataset.rdclass:
        raise ValidationFailure("RRSIG does not cover the RRset")

    candidate_keys = _find_candidate_keys(keys, rrsig)
    if candidate_keys is None:
        raise ValidationFailure("unknown key")

    if now is None:
        now = time.time()
    try:
        now_seconds = math.floor(now)
    except (OverflowError, ValueError) as exc:
        raise ValidationFailure("invalid validation time") from exc

    # RFC 4034 section 3.1.5: compare RRSIG times as 32-bit serial numbers.
    current = dns.serial.Serial(now_seconds)
    expiration = dns.serial.Serial(rrsig.expiration)
    # The exact expiration instant is inclusive, even when now is fractional.
    if not (current <= expiration) or (current == expiration and now > now_seconds):
        raise ValidationFailure("expired")
    if not (dns.serial.Serial(rrsig.inception) <= current):
        raise ValidationFailure("not yet valid")

    data = _make_rrsig_signature_data(rrset, rrsig, origin)

    # pylint: disable=possibly-used-before-assignment
    for candidate_key in candidate_keys:
        if not policy.ok_to_validate(candidate_key):
            continue
        try:
            _validate_signature(rrsig.signature, data, candidate_key)
            return
        except (InvalidSignature, ValidationFailure):
            # this happens on an individual validation failure
            continue
    # nothing verified -- raise failure:
    raise ValidationFailure("verify failure")


def _validate(
    rrset: dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset],
    rrsigset: dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset],
    keys: dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset],
    origin: dns.name.Name | None = None,
    now: float | None = None,
    policy: Policy | None = None,
) -> None:
    """Validate an RRset against a signature RRset, throwing an exception
    if none of the signatures validate.

    :param rrset: The RRset to validate — a :py:class:`dns.rrset.RRset` or a
        (:py:class:`dns.name.Name`, :py:class:`dns.rdataset.Rdataset`) tuple.
    :param rrsigset: The signature RRset — a :py:class:`dns.rrset.RRset` or a
        (:py:class:`dns.name.Name`, :py:class:`dns.rdataset.Rdataset`) tuple.
    :param keys: The key dictionary, keyed by :py:class:`dns.name.Name`, with
        :py:class:`dns.node.Node` or :py:class:`dns.rdataset.Rdataset` values.
    :param origin: The origin to use for relative names. Defaults to ``None``.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :param now: The current time in seconds since the epoch. If ``None``,
        the actual current time is used.
    :type now: int or ``None``
    :param policy: The policy to use. If ``None``, ``dns.dnssec.default_policy``
        is used (defaults to RFC 9904 policy).
    :type policy: :py:class:`dns.dnssec.Policy` or ``None``
    :raises ValidationFailure: If the signature is expired, not yet valid, the
        public key is invalid, the algorithm is unknown, verification fails, etc.
    """

    if policy is None:
        policy = default_policy

    if isinstance(origin, str):
        origin = dns.name.from_text(origin, dns.name.root)

    if isinstance(rrset, tuple):
        rrname = rrset[0]
    else:
        rrname = rrset.name

    if isinstance(rrsigset, tuple):
        rrsigname = rrsigset[0]
        rrsigrdataset = rrsigset[1]
    else:
        rrsigname = rrsigset.name
        rrsigrdataset = rrsigset

    rrname = rrname.choose_relativity(origin)
    rrsigname = rrsigname.choose_relativity(origin)
    if rrname != rrsigname:
        raise ValidationFailure("owner names do not match")

    for rrsig in rrsigrdataset:
        if not isinstance(rrsig, RRSIG):
            raise ValidationFailure("expected an RRSIG")
        try:
            _validate_rrsig(rrset, rrsig, keys, origin, now, policy)
            return
        except (ValidationFailure, UnsupportedAlgorithm):
            pass
    raise ValidationFailure("no RRSIGs validated")


def _sign(
    rrset: dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset],
    private_key: PrivateKey,
    signer: dns.name.Name,
    dnskey: DNSKEY,
    inception: datetime | str | int | float | None = None,
    expiration: datetime | str | int | float | None = None,
    lifetime: int | None = None,
    verify: bool = False,
    policy: Policy | None = None,
    origin: dns.name.Name | None = None,
    deterministic: bool = True,
) -> RRSIG:
    """Sign RRset using private key.

    :param rrset: The RRset to sign — a :py:class:`dns.rrset.RRset` or a
        (:py:class:`dns.name.Name`, :py:class:`dns.rdataset.Rdataset`) tuple.
    :param private_key: The private key to use for signing.
    :param signer: The signer's name.
    :type signer: :py:class:`dns.name.Name`
    :param dnskey: A DNSKEY matching *private_key*.
    :param inception: The signature inception time. If ``None``, the current
        time is used. If a ``str``, the format is ``"YYYYMMDDHHMMSS"`` or the
        number of seconds since the UNIX epoch. ``int`` and ``float`` values
        are interpreted as seconds since the UNIX epoch.
    :type inception: datetime, str, int, float, or ``None``
    :param expiration: The signature expiration time. If ``None``, the
        expiration is *inception* plus *lifetime*. Interpreted the same as
        *inception*.
    :type expiration: datetime, str, int, float, or ``None``
    :param lifetime: The signature lifetime in seconds. Only meaningful if
        *expiration* is ``None``.
    :type lifetime: int or ``None``
    :param verify: If ``True``, signatures will be verified after creation.
        Default is ``False``.
    :type verify: bool
    :param policy: The policy to use. If ``None``, ``dns.dnssec.default_policy``
        is used (defaults to RFC 9904 policy).
    :type policy: :py:class:`dns.dnssec.Policy` or ``None``
    :param origin: If ``None`` (the default), all names must be absolute.
        Otherwise, this origin is used to make names absolute when signing.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :param deterministic: If ``True`` (the default), use deterministic
        (reproducible) signatures when supported. Currently affects ECDSA.
    :type deterministic: bool
    :raises DeniedByPolicy: If the signature is denied by policy.
    """

    if policy is None:
        policy = default_policy
    if not policy.ok_to_sign(dnskey):
        raise DeniedByPolicy

    if isinstance(rrset, tuple):
        rdclass = rrset[1].rdclass
        rdtype = rrset[1].rdtype
        rrname = rrset[0]
        original_ttl = rrset[1].ttl
    else:
        rdclass = rrset.rdclass
        rdtype = rrset.rdtype
        rrname = rrset.name
        original_ttl = rrset.ttl

    if inception is not None:
        rrsig_inception = to_timestamp(inception)
    else:
        rrsig_inception = int(time.time())

    if expiration is not None:
        rrsig_expiration = to_timestamp(expiration)
    elif lifetime is not None:
        rrsig_expiration = rrsig_inception + lifetime
    else:
        raise ValueError("expiration or lifetime must be specified")

    # Derelativize now because we need a correct labels length for the
    # rrsig_template.
    if origin is not None:
        rrname = rrname.derelativize(origin)
    labels = len(rrname) - 1

    # Adjust labels appropriately for wildcards.
    if rrname.is_wild():
        labels -= 1

    rrsig_template = RRSIG(
        rdclass=rdclass,
        rdtype=dns.rdatatype.RRSIG,
        type_covered=rdtype,
        algorithm=dnskey.algorithm,
        labels=labels,
        original_ttl=original_ttl,
        expiration=rrsig_expiration,
        inception=rrsig_inception,
        key_tag=key_id(dnskey),
        signer=signer,
        signature=b"",
    )

    data = _make_rrsig_signature_data(rrset, rrsig_template, origin)

    # pylint: disable=possibly-used-before-assignment
    if isinstance(private_key, GenericPrivateKey):
        signing_key = private_key
    else:
        try:
            private_cls = get_algorithm_cls_from_dnskey(dnskey)
            signing_key = private_cls(key=private_key)
        except UnsupportedAlgorithm:
            raise TypeError("Unsupported key algorithm")

    signature = signing_key.sign(data, verify, deterministic)

    return rrsig_template.replace(signature=signature)


def _make_rrsig_signature_data(
    rrset: dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset],
    rrsig: RRSIG,
    origin: dns.name.Name | None = None,
) -> bytes:
    """Create signature rdata.

    :param rrset: The RRset to sign/validate — a :py:class:`dns.rrset.RRset`
        or a (:py:class:`dns.name.Name`, :py:class:`dns.rdataset.Rdataset`)
        tuple.
    :param rrsig: The signature to validate, or the signature template used
        when signing.
    :type rrsig: :py:class:`dns.rdata.Rdata`
    :param origin: The origin to use for relative names.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :raises UnsupportedAlgorithm: If the algorithm is recognized but not
        implemented.
    """

    if isinstance(origin, str):
        origin = dns.name.from_text(origin, dns.name.root)

    signer = rrsig.signer
    if not signer.is_absolute():
        if origin is None:
            raise ValidationFailure("relative RR name without an origin specified")
        signer = signer.derelativize(origin)

    # For convenience, allow the rrset to be specified as a (name,
    # rdataset) tuple as well as a proper rrset
    rrname, rdataset = _get_rrname_rdataset(rrset)

    data = b""
    wire = rrsig.to_wire(origin=signer)
    assert wire is not None  # for mypy
    data += wire[:18]
    data += rrsig.signer.to_digestable(signer)

    # Derelativize the name before considering labels.
    if not rrname.is_absolute():
        if origin is None:
            raise ValidationFailure("relative RR name without an origin specified")
        rrname = rrname.derelativize(origin)

    name_len = len(rrname)
    if rrname.is_wild() and rrsig.labels != name_len - 2:
        raise ValidationFailure("wild owner name has wrong label length")
    if name_len - 1 < rrsig.labels:
        raise ValidationFailure("owner name longer than RRSIG labels")
    elif rrsig.labels < name_len - 1:
        suffix = rrname.split(rrsig.labels + 1)[1]
        rrname = dns.name.from_text("*", suffix)
    rrnamebuf = rrname.to_digestable()
    rrfixed = struct.pack("!HHI", rdataset.rdtype, rdataset.rdclass, rrsig.original_ttl)
    rdatas = [rdata.to_digestable(origin) for rdata in rdataset]
    for rdata in sorted(rdatas):
        data += rrnamebuf
        data += rrfixed
        rrlen = struct.pack("!H", len(rdata))
        data += rrlen
        data += rdata

    return data


def _make_dnskey(
    public_key: PublicKey,
    algorithm: int | str,
    flags: int = Flag.ZONE,
    protocol: int = 3,
) -> DNSKEY:
    """Convert a public key to DNSKEY Rdata

    :param public_key: The public key to convert (a ``GenericPublicKey`` or
        ``cryptography.hazmat.primitives.asymmetric`` key).
    :param algorithm: The DNSKEY algorithm.
    :type algorithm: str or int
    :param flags: DNSKEY flags field.
    :type flags: int
    :param protocol: DNSKEY protocol field.
    :type protocol: int
    :raises ValueError: If the key algorithm parameters are unsupported.
    :raises TypeError: If the key type is unsupported.
    :raises UnsupportedAlgorithm: If the algorithm is unknown.
    :raises AlgorithmKeyMismatch: If the algorithm does not match the key type.
    :rtype: :py:class:`dns.rdtypes.ANY.DNSKEY.DNSKEY`
    """

    algorithm = Algorithm.make(algorithm)

    # pylint: disable=possibly-used-before-assignment
    if isinstance(public_key, GenericPublicKey):
        return public_key.to_dnskey(flags=flags, protocol=protocol)
    else:
        public_cls = get_algorithm_cls(algorithm).public_cls
        return public_cls(key=public_key).to_dnskey(flags=flags, protocol=protocol)


def _make_cdnskey(
    public_key: PublicKey,
    algorithm: int | str,
    flags: int = Flag.ZONE,
    protocol: int = 3,
) -> CDNSKEY:
    """Convert a public key to CDNSKEY Rdata

    :param public_key: The public key to convert
        (``cryptography.hazmat.primitives.asymmetric`` key for DNSSEC).
    :param algorithm: The DNSKEY algorithm.
    :type algorithm: str or int
    :param flags: DNSKEY flags field.
    :type flags: int
    :param protocol: DNSKEY protocol field.
    :type protocol: int
    :raises ValueError: If the key algorithm parameters are unsupported.
    :raises TypeError: If the key type is unsupported.
    :raises UnsupportedAlgorithm: If the algorithm is unknown.
    :raises AlgorithmKeyMismatch: If the algorithm does not match the key type.
    :rtype: :py:class:`dns.rdtypes.ANY.CDNSKEY.CDNSKEY`
    """

    dnskey = _make_dnskey(public_key, algorithm, flags, protocol)

    return CDNSKEY(
        rdclass=dnskey.rdclass,
        rdtype=dns.rdatatype.CDNSKEY,
        flags=dnskey.flags,
        protocol=dnskey.protocol,
        algorithm=dnskey.algorithm,
        key=dnskey.key,
    )


def nsec3_hash(
    domain: dns.name.Name | str,
    salt: str | bytes | None,
    iterations: int,
    algorithm: int | str,
) -> str:
    """
    Calculate the NSEC3 hash, according to
    https://tools.ietf.org/html/rfc5155#section-5

    :param domain: The name to hash.
    :type domain: :py:class:`dns.name.Name` or str
    :param salt: The hash salt. If a string, it is decoded as a hex string.
    :type salt: str, bytes, or ``None``
    :param iterations: The number of iterations.
    :type iterations: int
    :param algorithm: The hash algorithm. The only defined algorithm is SHA1.
    :type algorithm: str or int
    :rtype: str
    """

    try:
        if isinstance(algorithm, str):
            algorithm = NSEC3Hash[algorithm.upper()]
    except Exception:
        raise ValueError("Wrong hash algorithm (only SHA1 is supported)")

    if algorithm != NSEC3Hash.SHA1:
        raise ValueError("Wrong hash algorithm (only SHA1 is supported)")

    if salt is None:
        salt_encoded = b""
    elif isinstance(salt, str):
        if len(salt) % 2 == 0:
            salt_encoded = bytes.fromhex(salt)
        else:
            raise ValueError("Invalid salt length")
    else:
        salt_encoded = salt

    if not isinstance(domain, dns.name.Name):
        domain = dns.name.from_text(domain)
    domain_encoded = domain.canonicalize().to_wire()
    assert domain_encoded is not None

    digest = hashlib.sha1(domain_encoded + salt_encoded).digest()
    for _ in range(iterations):
        digest = hashlib.sha1(digest + salt_encoded).digest()

    return base64.b32hexencode(digest).decode("utf-8")


def make_ds_rdataset(
    rrset: dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset],
    algorithms: set[DSDigest | str],
    origin: dns.name.Name | None = None,
) -> dns.rdataset.Rdataset:
    """Create a DS record from DNSKEY/CDNSKEY/CDS.

    :param rrset: The RRset — a :py:class:`dns.rrset.RRset` or a
        (:py:class:`dns.name.Name`, :py:class:`dns.rdataset.Rdataset`) tuple.
    :param algorithms: A set of hash algorithms. Currently supported:
        ``"SHA1"``, ``"SHA256"``, ``"SHA384"`` (case-insensitive). If the
        RRset is a CDS, only digest algorithms matching *algorithms* are
        accepted.
    :type algorithms: set of str or int
    :param origin: If the key name is relative, it will be made absolute
        using this origin.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :raises UnsupportedAlgorithm: If any algorithm is unknown.
    :raises ValueError: If the given RRset is not usable.
    :rtype: :py:class:`dns.rdataset.Rdataset`
    """

    rrname, rdataset = _get_rrname_rdataset(rrset)

    if rdataset.rdtype not in (
        dns.rdatatype.DNSKEY,
        dns.rdatatype.CDNSKEY,
        dns.rdatatype.CDS,
    ):
        raise ValueError("rrset not a DNSKEY/CDNSKEY/CDS")

    _algorithms = set()
    for algorithm in algorithms:
        try:
            if isinstance(algorithm, str):
                algorithm = DSDigest[algorithm.upper()]
        except Exception:
            raise UnsupportedAlgorithm(f'unsupported algorithm "{algorithm}"')
        _algorithms.add(algorithm)

    if rdataset.rdtype == dns.rdatatype.CDS:
        res = []
        for rdata in cds_rdataset_to_ds_rdataset(rdataset):
            if rdata.digest_type in _algorithms:
                res.append(rdata)
        if len(res) == 0:
            raise ValueError("no acceptable CDS rdata found")
        return dns.rdataset.from_rdata_list(rdataset.ttl, res)

    res = []
    for algorithm in _algorithms:
        res.extend(dnskey_rdataset_to_cds_rdataset(rrname, rdataset, algorithm, origin))
    return dns.rdataset.from_rdata_list(rdataset.ttl, res)


def cds_rdataset_to_ds_rdataset(
    rdataset: dns.rdataset.Rdataset,
) -> dns.rdataset.Rdataset:
    """Create a CDS record from DS.

    :param rdataset: The CDS rdataset to convert to DS.
    :type rdataset: :py:class:`dns.rdataset.Rdataset`
    :raises ValueError: If the rdataset is not CDS.
    :rtype: :py:class:`dns.rdataset.Rdataset`
    """

    if rdataset.rdtype != dns.rdatatype.CDS:
        raise ValueError("rdataset not a CDS")
    res = []
    for rdata in rdataset:
        res.append(
            CDS(
                rdclass=rdata.rdclass,
                rdtype=dns.rdatatype.DS,
                key_tag=rdata.key_tag,
                algorithm=rdata.algorithm,
                digest_type=rdata.digest_type,
                digest=rdata.digest,
            )
        )
    return dns.rdataset.from_rdata_list(rdataset.ttl, res)


def dnskey_rdataset_to_cds_rdataset(
    name: dns.name.Name | str,
    rdataset: dns.rdataset.Rdataset,
    algorithm: DSDigest | str,
    origin: dns.name.Name | None = None,
) -> dns.rdataset.Rdataset:
    """Create a CDS record from DNSKEY/CDNSKEY.

    :param name: The owner name of the CDS record.
    :type name: :py:class:`dns.name.Name` or str
    :param rdataset: The DNSKEY/CDNSKEY rdataset to create CDS for.
    :type rdataset: :py:class:`dns.rdataset.Rdataset`
    :param algorithm: The hash algorithm. Currently supported: ``"SHA1"``,
        ``"SHA256"``, ``"SHA384"`` (case-insensitive).
    :type algorithm: str or int
    :param origin: If the key name is relative, it will be made absolute
        using this origin.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :raises UnsupportedAlgorithm: If the algorithm is unknown.
    :raises ValueError: If the rdataset is not DNSKEY/CDNSKEY.
    :rtype: :py:class:`dns.rdataset.Rdataset`
    """

    if rdataset.rdtype not in (dns.rdatatype.DNSKEY, dns.rdatatype.CDNSKEY):
        raise ValueError("rdataset not a DNSKEY/CDNSKEY")
    res = []
    for rdata in rdataset:
        res.append(make_cds(name, rdata, algorithm, origin))
    return dns.rdataset.from_rdata_list(rdataset.ttl, res)


def dnskey_rdataset_to_cdnskey_rdataset(
    rdataset: dns.rdataset.Rdataset,
) -> dns.rdataset.Rdataset:
    """Create a CDNSKEY record from DNSKEY.

    :param rdataset: The DNSKEY rdataset to convert to CDNSKEY.
    :type rdataset: :py:class:`dns.rdataset.Rdataset`
    :rtype: :py:class:`dns.rdataset.Rdataset`
    """

    if rdataset.rdtype != dns.rdatatype.DNSKEY:
        raise ValueError("rdataset not a DNSKEY")
    res = []
    for rdata in rdataset:
        res.append(
            CDNSKEY(
                rdclass=rdataset.rdclass,
                rdtype=rdataset.rdtype,
                flags=rdata.flags,
                protocol=rdata.protocol,
                algorithm=rdata.algorithm,
                key=rdata.key,
            )
        )
    return dns.rdataset.from_rdata_list(rdataset.ttl, res)


def default_rrset_signer(
    txn: dns.transaction.Transaction,
    rrset: dns.rrset.RRset,
    signer: dns.name.Name,
    ksks: list[tuple[PrivateKey, DNSKEY]],
    zsks: list[tuple[PrivateKey, DNSKEY]],
    inception: datetime | str | int | float | None = None,
    expiration: datetime | str | int | float | None = None,
    lifetime: int | None = None,
    policy: Policy | None = None,
    origin: dns.name.Name | None = None,
    deterministic: bool = True,
) -> None:
    """Default RRset signer"""

    if rrset.rdtype in set(
        [
            dns.rdatatype.RdataType.DNSKEY,
            dns.rdatatype.RdataType.CDS,
            dns.rdatatype.RdataType.CDNSKEY,
        ]
    ):
        keys = ksks
    else:
        keys = zsks

    for private_key, dnskey in keys:
        rrsig = sign(
            rrset=rrset,
            private_key=private_key,
            dnskey=dnskey,
            inception=inception,
            expiration=expiration,
            lifetime=lifetime,
            signer=signer,
            policy=policy,
            origin=origin,
            deterministic=deterministic,
        )
        txn.add(rrset.name, rrset.ttl, rrsig)


def sign_zone(
    zone: dns.zone.Zone,
    txn: dns.transaction.Transaction | None = None,
    keys: list[tuple[PrivateKey, DNSKEY]] | None = None,
    add_dnskey: bool = True,
    dnskey_ttl: int | None = None,
    inception: datetime | str | int | float | None = None,
    expiration: datetime | str | int | float | None = None,
    lifetime: int | None = None,
    nsec3: NSEC3PARAM | None = None,
    rrset_signer: RRsetSigner | None = None,
    policy: Policy | None = None,
    deterministic: bool = True,
) -> None:
    """Sign zone.

    :param zone: The zone to sign.
    :type zone: :py:class:`dns.zone.Zone`
    :param txn: An optional transaction to use for signing.
    :type txn: :py:class:`dns.transaction.Transaction` or ``None``
    :param keys: A list of (``PrivateKey``, ``DNSKEY``) tuples to use for
        signing. KSK/ZSK roles are assigned automatically if the SEP flag is
        used; otherwise all RRsets are signed by all keys.
    :param add_dnskey: If ``True`` (the default), all specified DNSKEYs are
        automatically added to the zone on signing.
    :type add_dnskey: bool
    :param dnskey_ttl: The TTL for DNSKEY RRs. If not specified, uses the TTL
        of the existing DNSKEY RRset or the SOA RRset.
    :type dnskey_ttl: int or ``None``
    :param inception: The signature inception time. If ``None``, the current
        time is used. If a ``str``, the format is ``"YYYYMMDDHHMMSS"`` or
        seconds since UNIX epoch. ``int`` and ``float`` are seconds since epoch.
    :type inception: datetime, str, int, float, or ``None``
    :param expiration: The signature expiration time. If ``None``, the
        expiration is *inception* plus *lifetime*. Interpreted the same as
        *inception*.
    :type expiration: datetime, str, int, float, or ``None``
    :param lifetime: The signature lifetime in seconds. Only meaningful if
        *expiration* is ``None``.
    :type lifetime: int or ``None``
    :param nsec3: If specified, configures signing using NSEC3. Not yet
        implemented.
    :param rrset_signer: An optional function for signing RRsets, accepting
        two arguments: transaction and RRset. If not specified,
        ``dns.dnssec.default_rrset_signer`` is used.
    :param deterministic: If ``True`` (the default), use deterministic
        (reproducible) signatures when supported. Currently affects ECDSA.
    :type deterministic: bool
    """

    ksks = []
    zsks = []

    # if we have both KSKs and ZSKs, split by SEP flag. if not, sign all
    # records with all keys
    if keys:
        for key in keys:
            if key[1].flags & Flag.SEP:
                ksks.append(key)
            else:
                zsks.append(key)
        if not ksks:
            ksks = keys
        if not zsks:
            zsks = keys
    else:
        keys = []

    if txn:
        cm: contextlib.AbstractContextManager = contextlib.nullcontext(txn)
    else:
        cm = zone.writer()

    if zone.origin is None:
        raise ValueError("no zone origin")

    with cm as _txn:
        if add_dnskey:
            if dnskey_ttl is None:
                dnskey = _txn.get(zone.origin, dns.rdatatype.DNSKEY)
                if dnskey:
                    dnskey_ttl = dnskey.ttl
                else:
                    soa = _txn.get(zone.origin, dns.rdatatype.SOA)
                    if soa is None:
                        raise ValueError("zone does not have an SOA at the origin")
                    dnskey_ttl = soa.ttl
            for _, dnskey in keys:
                _txn.add(zone.origin, dnskey_ttl, dnskey)

        if nsec3:
            raise NotImplementedError("Signing with NSEC3 not yet implemented")
        else:
            _rrset_signer = rrset_signer or functools.partial(
                default_rrset_signer,
                signer=zone.origin,
                ksks=ksks,
                zsks=zsks,
                inception=inception,
                expiration=expiration,
                lifetime=lifetime,
                policy=policy,
                origin=zone.origin,
                deterministic=deterministic,
            )
            return _sign_zone_nsec(zone, _txn, _rrset_signer)


def _sign_zone_nsec(
    zone: dns.zone.Zone,
    txn: dns.transaction.Transaction,
    rrset_signer: RRsetSigner | None = None,
) -> None:
    """NSEC zone signer"""

    def _txn_add_nsec(
        txn: dns.transaction.Transaction,
        name: dns.name.Name,
        next_secure: dns.name.Name | None,
        rdclass: dns.rdataclass.RdataClass,
        ttl: int,
        rrset_signer: RRsetSigner | None = None,
    ) -> None:
        """NSEC zone signer helper"""
        mandatory_types = set(
            [dns.rdatatype.RdataType.RRSIG, dns.rdatatype.RdataType.NSEC]
        )
        node = txn.get_node(name)
        if node and next_secure:
            types = (
                set([rdataset.rdtype for rdataset in node.rdatasets]) | mandatory_types
            )
            windows = Bitmap.from_rdtypes(list(types))
            rrset = dns.rrset.from_rdata(
                name,
                ttl,
                NSEC(
                    rdclass=rdclass,
                    rdtype=dns.rdatatype.RdataType.NSEC,
                    next=next_secure,
                    windows=windows,
                ),
            )
            txn.add(rrset)
            if rrset_signer:
                rrset_signer(txn, rrset)

    rrsig_ttl = zone.get_soa(txn).minimum
    delegation = None
    last_secure = None

    for name in sorted(txn.iterate_names()):
        if delegation and name.is_subdomain(delegation):
            # names below delegations are not secure
            continue
        elif txn.get(name, dns.rdatatype.NS) and name != zone.origin:
            # inside delegation
            delegation = name
        else:
            # outside delegation
            delegation = None

        if rrset_signer:
            node = txn.get_node(name)
            if node:
                for rdataset in node.rdatasets:
                    if rdataset.rdtype == dns.rdatatype.RRSIG:
                        # do not sign RRSIGs
                        continue
                    elif delegation and rdataset.rdtype != dns.rdatatype.DS:
                        # do not sign delegations except DS records
                        continue
                    else:
                        rrset = dns.rrset.from_rdata(name, rdataset.ttl, *rdataset)
                        rrset_signer(txn, rrset)

        # We need "is not None" as the empty name is False because its length is 0.
        if last_secure is not None:
            _txn_add_nsec(txn, last_secure, name, zone.rdclass, rrsig_ttl, rrset_signer)
        last_secure = name

    if last_secure is not None:
        _txn_add_nsec(
            txn, last_secure, zone.origin, zone.rdclass, rrsig_ttl, rrset_signer
        )


class NegativeProofType(Enum):
    """The kind of authenticated negative answer an NSEC proof establishes."""

    #: The queried name does not exist in the zone (an NXDOMAIN answer).
    NAME_DOES_NOT_EXIST = 1
    #: The queried name exists, but has no RRset of the queried type
    #: (a NODATA answer).
    TYPE_DOES_NOT_EXIST = 2


class NSECRole(Enum):
    """The role a particular NSEC RRset plays in a negative proof."""

    #: The NSEC proves the closest encloser name exists.
    CLOSEST_ENCLOSER = 1
    #: The NSEC's canonical-order interval contains the next closer name.
    NEXT_CLOSER = 2
    #: The NSEC's canonical-order interval contains the wildcard
    #: ``*.<closest encloser>``, proving no matching wildcard exists.
    WILDCARD_POSSIBILITY = 3
    #: The NSEC is owned by the queried name itself.
    EXACT_NAME = 4
    #: The NSEC is owned by the wildcard ``*.<closest encloser>``.
    WILDCARD_EXPANSION = 5


@dataclasses.dataclass(frozen=True)
class NSECEvidence:
    """One NSEC RRset that participates in a negative proof.

    Every entry has an RRSIG RRset that validated against the trusted key
    set at the validation time, and belongs to the queried zone.
    """

    #: Every role this NSEC plays in the proof. A single NSEC can cover both
    #: the next closer name and the possible wildcard, so it may have more
    #: than one role.
    roles: tuple[NSECRole, ...]
    #: The validated NSEC RRset.
    nsec_rrset: dns.rrset.RRset
    #: The RRSIG RRset that authenticated *nsec_rrset*.
    rrsig_rrset: dns.rrset.RRset

    @property
    def name(self) -> dns.name.Name:
        """The owner name of the NSEC RRset."""
        return self.nsec_rrset.name

    @property
    def nsec(self) -> NSEC:
        """The single NSEC rdata of the NSEC RRset."""
        return cast(NSEC, next(iter(self.nsec_rrset)))

    def has_role(self, role: NSECRole) -> bool:
        """Return whether this evidence entry fulfills *role*."""
        return role in self.roles


@dataclasses.dataclass(frozen=True)
class NSECNegativeProof:
    """The result of successfully validating an NSEC negative answer."""

    #: Whether the name is absent entirely, or present without the type.
    proof: NegativeProofType
    #: The zone apex that the proof was made in.
    zone: dns.name.Name
    #: The closest encloser of the queried name within the zone.
    closest_encloser: dns.name.Name
    #: The NSEC RRsets that actually support the conclusion, in proof order.
    evidence: tuple[NSECEvidence, ...]

    @property
    def is_nxdomain(self) -> bool:
        """``True`` if the proof establishes that the name does not exist."""
        return self.proof == NegativeProofType.NAME_DOES_NOT_EXIST

    @property
    def is_nodata(self) -> bool:
        """``True`` if the name exists but has no RRset of the queried type."""
        return self.proof == NegativeProofType.TYPE_DOES_NOT_EXIST


def _order_lt(name1: dns.name.Name, name2: dns.name.Name) -> bool:
    # Canonical DNS name ordering (RFC 4034 section 6.1); never compare
    # textual forms.
    return name1.fullcompare(name2)[1] < 0


def _nsec_covers(
    owner: dns.name.Name,
    next_name: dns.name.Name,
    target: dns.name.Name,
    zone: dns.name.Name,
) -> bool:
    """Does the NSEC interval (owner, next_name) canonically contain target?

    The interval is the set of names strictly after *owner* and strictly
    before *next_name* in the canonical order.  When *next_name* is the zone
    apex, the interval wraps around the end of the zone.  The endpoints are
    never covered.
    """
    if next_name == zone:
        # Wrap-around interval: every in-zone name strictly greater than the
        # NSEC owner is covered (the apex itself is an endpoint, never covered).
        return _order_lt(owner, target) and target != zone
    return _order_lt(owner, target) and _order_lt(target, next_name)


def _nsec_has_type(nsec: NSEC, rdtype: dns.rdatatype.RdataType | int) -> bool:
    rdtype = int(rdtype)
    window = rdtype // 256
    octet = (rdtype % 256) // 8
    bit = 0x80 >> (rdtype % 8)
    for nsec_window, bitmap in nsec.windows:
        if nsec_window == window:
            return octet < len(bitmap) and bool(bitmap[octet] & bit)
        if nsec_window > window:
            return False
    return False


def _as_absolute_name(
    value: dns.name.Name | str, origin: dns.name.Name | None, what: str
) -> dns.name.Name:
    if isinstance(value, str):
        value = dns.name.from_text(value, origin)
    if not value.is_absolute():
        if origin is None:
            raise ValidationFailure(f"relative {what} without an origin specified")
        value = value.derelativize(origin)
    return value.canonicalize()


def _rrset_key(
    rrset: dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset],
) -> tuple[dns.name.Name, dns.rdataset.Rdataset]:
    return _get_rrname_rdataset(rrset)


def _absolute_signer(
    signer: dns.name.Name, origin: dns.name.Name | None
) -> dns.name.Name:
    if not signer.is_absolute():
        if origin is None:
            raise ValidationFailure("relative RRSIG signer without an origin specified")
        signer = signer.derelativize(origin)
    return signer.canonicalize()


def _index_nsecs(
    nsec_rrsets: Iterable[
        dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset]
    ],
    origin: dns.name.Name | None,
) -> dict[dns.name.Name, dns.rdataset.Rdataset]:
    nsecs: dict[dns.name.Name, dns.rdataset.Rdataset] = {}
    for item in nsec_rrsets:
        name, rdataset = _rrset_key(item)
        name = _as_absolute_name(name, origin, "NSEC owner name")
        if rdataset.rdtype == dns.rdatatype.NSEC3:
            raise NSEC3Unsupported(
                "NSEC3 proofs are not supported by the NSEC validator"
            )
        if rdataset.rdtype != dns.rdatatype.NSEC:
            raise ValidationFailure("expected an NSEC RRset")
        for rdata in rdataset:
            if not isinstance(rdata, NSEC):
                raise ValidationFailure("expected an NSEC rdata")
        existing = nsecs.get(name)
        if existing is not None and list(existing) != list(rdataset):
            raise ValidationFailure("contradictory NSEC rdata at the same owner name")
        nsecs[name] = rdataset
    return nsecs


def _index_rrsigs(
    rrsig_rrsets: Iterable[
        dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset]
    ],
    origin: dns.name.Name | None,
) -> dict[dns.name.Name, list[RRSIG]]:
    rrsigs: dict[dns.name.Name, list[RRSIG]] = {}
    for item in rrsig_rrsets:
        name, rdataset = _rrset_key(item)
        name = _as_absolute_name(name, origin, "RRSIG owner name")
        if rdataset.rdtype != dns.rdatatype.RRSIG:
            raise ValidationFailure("expected an RRSIG RRset")
        for rdata in rdataset:
            if not isinstance(rdata, RRSIG):
                raise ValidationFailure("expected an RRSIG rdata")
            if rdata.type_covered == dns.rdatatype.NSEC3:
                raise NSEC3Unsupported(
                    "NSEC3 proofs are not supported by the NSEC validator"
                )
            if rdata.type_covered != dns.rdatatype.NSEC:
                raise ValidationFailure("RRSIG does not cover NSEC")
        rrsigs.setdefault(name, []).extend(
            rdata for rdata in rdataset if isinstance(rdata, RRSIG)
        )
    return rrsigs


def _authenticate_nsec(
    owner: dns.name.Name,
    nsec_rdataset: dns.rdataset.Rdataset,
    rrsigs: dict[dns.name.Name, list[RRSIG]],
    keys: dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset],
    now: float | None,
    policy: Policy,
    origin: dns.name.Name | None,
) -> tuple[dns.rrset.RRset, dns.rrset.RRset]:
    """Validate the signature chain for one NSEC RRset.

    Returns the NSEC RRset and the RRSIG RRset that validated it.  Raises
    :class:`~dns.exception.ValidationFailure` if no usable signature exists or
    every signature fails.
    """
    candidate_rrsigs = rrsigs.get(owner)
    if not candidate_rrsigs:
        raise ValidationFailure(f"NSEC at {owner} has no RRSIG")

    nsec_rrset = dns.rrset.from_rdata(owner, nsec_rdataset.ttl, *nsec_rdataset)
    failures: list[str] = []
    for rrsig in candidate_rrsigs:
        signer = _absolute_signer(rrsig.signer, origin)
        if keys.get(signer) is None:
            failures.append(f"no trusted key for signer {signer}")
            continue
        rrsig_rrset = dns.rrset.from_rdata(owner, rrsig.original_ttl, rrsig)
        try:
            _validate_rrsig(
                (owner, nsec_rdataset),
                rrsig,
                keys,
                origin,
                now,
                policy,
            )
            return nsec_rrset, rrsig_rrset
        except (ValidationFailure, UnsupportedAlgorithm) as exc:
            failures.append(str(exc))
    raise ValidationFailure(
        f"NSEC at {owner} has no valid RRSIG: {'; '.join(failures)}"
    )


def _find_closest_encloser(
    qname: dns.name.Name,
    nsec_owners: set[dns.name.Name],
    zone: dns.name.Name,
) -> dns.name.Name:
    # The closest encloser is the longest existing ancestor of qname within
    # the zone.  The zone apex always exists.
    candidate = qname
    while candidate != zone:
        candidate = candidate.parent()
        if candidate in nsec_owners:
            return candidate
    return zone


def validate_nsec_negative_proof(
    qname: dns.name.Name | str,
    qtype: dns.rdatatype.RdataType | str,
    keys: dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset],
    nsec_rrsets: Iterable[
        dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset]
    ],
    rrsig_rrsets: Iterable[
        dns.rrset.RRset | tuple[dns.name.Name, dns.rdataset.Rdataset]
    ],
    now: float | None = None,
    origin: dns.name.Name | None = None,
    policy: Policy | None = None,
    cname_chain: Iterable[dns.name.Name | str] | None = None,
) -> NSECNegativeProof:
    """Validate a traditional NSEC denial-of-existence proof.

    This implements the NSEC parts of RFC 4035 section 5.4 (with the
    clarifications of RFC 7129).  It distinguishes an authenticated NXDOMAIN
    (the queried name does not exist) from an authenticated NODATA (the name
    exists but has no RRset of the queried type), and verifies the closest
    encloser, next closer, wildcard-possibility, exact-name and
    wildcard-expansion NSECs that the conclusion depends on, including
    canonical-order wrap-around at the zone apex.

    Every NSEC used in the conclusion must validate against *keys* at time
    *now* and be signed by the zone whose apex encloses the queried name;
    valid NSECs from other zones or unrelated parts of the namespace cannot
    be stitched into a proof.

    :param qname: The queried name.
    :type qname: :py:class:`dns.name.Name` or str
    :param qtype: The queried RR type.
    :type qtype: :py:class:`dns.rdatatype.RdataType` or str
    :param keys: The trusted DNSKEY dictionary, keyed by signer name, as used
        by :func:`validate_rrsig`.
    :param nsec_rrsets: The NSEC RRsets supplied as proof, each an
        :py:class:`dns.rrset.RRset` or a ``(name, rdataset)`` tuple.
    :param rrsig_rrsets: The RRSIG RRsets (covering NSEC) supplied as proof,
        in the same form.
    :param now: The fixed validation time in seconds since the epoch. If
        ``None``, the actual current time is used.
    :type now: float or ``None``
    :param origin: Origin used to derelativize any relative names. If
        ``None`` (the default), all names must be absolute.
    :type origin: :py:class:`dns.name.Name` or ``None``
    :param policy: The policy to use. If ``None``,
        :py:data:`default_policy` is used.
    :type policy: :py:class:`Policy` or ``None``
    :param cname_chain: Optional names traversed by a CNAME chain before the
        negative answer. If given, the last name is the terminal name that
        the proof must actually cover; the intermediate CNAME RRsets must be
        validated separately with :func:`validate`.
    :type cname_chain: iterable of :py:class:`dns.name.Name` or str, or
        ``None``
    :raises IncompleteProof: If the records are insufficient to establish
        the negative answer.
    :raises ValidationFailure: If the proof is contradictory, a required
        signature is missing/expired/bad, or records are from the wrong
        zone.
    :raises NSEC3Unsupported: If NSEC3 material is presented.
    :rtype: :py:class:`NSECNegativeProof`
    """

    if policy is None:
        policy = default_policy
    if isinstance(origin, str):
        origin = dns.name.from_text(origin, dns.name.root)

    qtype = dns.rdatatype.RdataType.make(qtype)
    qname = _as_absolute_name(qname, origin, "query name")

    chain: list[dns.name.Name] = []
    if cname_chain is not None:
        chain = [
            _as_absolute_name(name, origin, "CNAME chain name") for name in cname_chain
        ]
    target = chain[-1] if chain else qname

    nsec_map = _index_nsecs(nsec_rrsets, origin)
    rrsig_map = _index_rrsigs(rrsig_rrsets, origin)

    if not nsec_map:
        raise IncompleteProof("no NSEC records provided")

    # The zone is identified by the signer names on the NSEC RRSIGs. Only a
    # signer whose apex encloses the target can possibly prove this answer.
    zones: set[dns.name.Name] = set()
    for nsec_name in nsec_map:
        for rrsig in rrsig_map.get(nsec_name, ()):
            zones.add(_absolute_signer(rrsig.signer, origin))
    if not zones:
        raise IncompleteProof("no NSEC RRSIGs provided")

    candidate_zones = {zone for zone in zones if target.is_subdomain(zone)}
    if not candidate_zones:
        raise ValidationFailure(
            "no signed NSEC belongs to a zone enclosing the queried name"
        )
    if len(candidate_zones) > 1:
        raise ValidationFailure("NSEC records are signed by multiple enclosing zones")
    zone = next(iter(candidate_zones))

    # NSECs outside the proving zone (even validly signed ones) cannot take
    # part in this proof.
    in_zone = {name for name in nsec_map if name.is_subdomain(zone)}
    if not in_zone:
        raise IncompleteProof("no NSEC records belong to the queried zone")

    # Each participating NSEC appears once in evidence, carrying every role
    # it plays in the proof. Removing any entry (or its RRSIG) breaks it.
    evidence_by_name: dict[dns.name.Name, NSECEvidence] = {}

    def use(owner: dns.name.Name, role: NSECRole) -> NSECEvidence:
        if owner not in nsec_map:
            raise IncompleteProof(f"missing NSEC required for {role.name}: {owner}")
        if not owner.is_subdomain(zone):
            raise ValidationFailure(
                f"NSEC at {owner} is outside the proving zone {zone}"
            )
        existing = evidence_by_name.get(owner)
        if existing is not None:
            if role not in existing.roles:
                evidence_by_name[owner] = dataclasses.replace(
                    existing, roles=(*existing.roles, role)
                )
            return evidence_by_name[owner]
        nsec_rrset, rrsig_rrset = _authenticate_nsec(
            owner, nsec_map[owner], rrsig_map, keys, now, policy, origin
        )
        entry = NSECEvidence((role,), nsec_rrset, rrsig_rrset)
        evidence_by_name[owner] = entry
        return entry

    def covering(covered: dns.name.Name, role: NSECRole) -> NSECEvidence | None:
        # The covering NSEC is the in-zone NSEC with the greatest owner
        # canonically less than the covered name, whose interval contains it.
        best: dns.name.Name | None = None
        for owner in in_zone:
            nsec = cast(NSEC, next(iter(nsec_map[owner])))
            next_name = _as_absolute_name(nsec.next, origin, "NSEC next name")
            if _nsec_covers(owner, next_name, covered, zone):
                if best is None or _order_lt(best, owner):
                    best = owner
        if best is None:
            return None
        return use(best, role)

    if target in nsec_map:
        # The target name exists; this can only be a NODATA proof.
        exact = use(target, NSECRole.EXACT_NAME)
        nsec = exact.nsec
        if _nsec_has_type(nsec, qtype):
            raise ValidationFailure(
                f"NSEC at {target} asserts the queried type "
                f"{dns.rdatatype.to_text(qtype)} exists"
            )
        if qtype != dns.rdatatype.CNAME and _nsec_has_type(nsec, dns.rdatatype.CNAME):
            raise ValidationFailure(
                f"NSEC at {target} shows a CNAME; validate the CNAME target"
            )
        return NSECNegativeProof(
            NegativeProofType.TYPE_DOES_NOT_EXIST,
            zone,
            target,
            tuple(evidence_by_name.values()),
        )

    closest_encloser = _find_closest_encloser(target, set(in_zone), zone)

    # (1) The closest encloser must be proven to exist.
    use(closest_encloser, NSECRole.CLOSEST_ENCLOSER)

    # next closer name: one more label than the closest encloser, taken from
    # the target (RFC 4035 section 5.4 / RFC 7129).
    next_closer = dns.name.Name([target.labels[0], *list(closest_encloser.labels)])

    # (2) An NSEC covering the next closer name proves the target name is
    # absent. This is required for both NXDOMAIN and wildcard NODATA.
    nc_evidence = covering(next_closer, NSECRole.NEXT_CLOSER)
    if nc_evidence is None:
        raise IncompleteProof(f"no NSEC covers the next closer name {next_closer}")

    # A matching wildcard would be "*.<some ancestor of the target>". Walk
    # the strict ancestors of the target from shallowest (the closest
    # encloser) to deepest and look for a signed wildcard NSEC at each level;
    # only the deepest matching one can synthesize the target.
    wildcard_name: dns.name.Name | None = None
    # A wildcard "*.<suffix>" matching the target has one fewer label than
    # the target, so suffix depths run from the closest encloser up to
    # len(target) - 1.
    deepest_suffix_depth = len(target.labels) - 1
    for depth in range(len(closest_encloser.labels), deepest_suffix_depth + 1):
        _, suffix = target.split(depth)
        candidate = dns.name.Name([b"*", *list(suffix.labels)])
        if candidate in nsec_map:
            wildcard_name = candidate
            break

    if wildcard_name is not None:
        # A signed wildcard exists. If it lacks the queried type the answer
        # is a wildcard NODATA (RFC 7129 section 5.4); if it has the type,
        # a wildcard answer should have been given instead.
        wildcard_exact = use(wildcard_name, NSECRole.WILDCARD_EXPANSION)
        nsec = wildcard_exact.nsec
        if _nsec_has_type(nsec, qtype):
            raise ValidationFailure(
                f"wildcard {wildcard_name} has the queried type, so a "
                "negative answer is contradicted"
            )
        return NSECNegativeProof(
            NegativeProofType.TYPE_DOES_NOT_EXIST,
            zone,
            closest_encloser,
            tuple(evidence_by_name.values()),
        )

    # No wildcard NSEC exists, so an NSEC must cover *.<closest encloser>,
    # proving no wildcard at the closest encloser could have synthesized the
    # name. It may be the same NSEC as (2).
    wildcard = dns.name.Name([b"*", *list(closest_encloser.labels)])
    wildcard_evidence = covering(wildcard, NSECRole.WILDCARD_POSSIBILITY)
    if wildcard_evidence is None:
        raise IncompleteProof(f"no NSEC covers the possible wildcard {wildcard}")

    return NSECNegativeProof(
        NegativeProofType.NAME_DOES_NOT_EXIST,
        zone,
        closest_encloser,
        tuple(evidence_by_name.values()),
    )


def validate_nsec_negative_message(
    qname: dns.name.Name | str,
    qtype: dns.rdatatype.RdataType | str,
    keys: dict[dns.name.Name, dns.node.Node | dns.rdataset.Rdataset],
    message: dns.message.Message,
    now: float | None = None,
    origin: dns.name.Name | None = None,
    policy: Policy | None = None,
) -> NSECNegativeProof:
    """Validate the NSEC denial-of-existence proof in a DNS response.

    This is a convenience wrapper around
    :func:`validate_nsec_negative_proof` that extracts the NSEC and
    NSEC-covering RRSIG RRsets from *message*'s answer and authority
    sections.

    A CNAME chain is not followed here; validate each CNAME RRset with
    :func:`validate` and, if the negative answer is about the chain's
    terminal name, call :func:`validate_nsec_negative_proof` directly with
    that name.

    :param message: A DNS response carrying NSEC and RRSIG records.
    :type message: :py:class:`dns.message.Message`
    :raises NSEC3Unsupported: If the message carries NSEC3 records.
    :rtype: :py:class:`NSECNegativeProof`
    """
    nsec_rrsets: list[dns.rrset.RRset] = []
    rrsig_rrsets: list[dns.rrset.RRset] = []
    for section in (message.answer, message.authority):
        for rrset in section:
            if rrset.rdtype == dns.rdatatype.NSEC:
                nsec_rrsets.append(rrset)
            elif rrset.rdtype == dns.rdatatype.NSEC3:
                raise NSEC3Unsupported(
                    "NSEC3 proofs are not supported by the NSEC validator"
                )
            elif rrset.rdtype == dns.rdatatype.RRSIG:
                if rrset.covers == dns.rdatatype.NSEC3:
                    raise NSEC3Unsupported(
                        "NSEC3 proofs are not supported by the NSEC validator"
                    )
                if rrset.covers == dns.rdatatype.NSEC:
                    rrsig_rrsets.append(rrset)

    return validate_nsec_negative_proof(
        qname,
        qtype,
        keys,
        nsec_rrsets,
        rrsig_rrsets,
        now=now,
        origin=origin,
        policy=policy,
    )


_validate_nsec_negative_proof = validate_nsec_negative_proof
_validate_nsec_negative_message = validate_nsec_negative_message


def _need_pyca(*args, **kwargs):
    raise ImportError(
        "DNSSEC validation requires python cryptography"
    )  # pragma: no cover


if dns._features.have("dnssec"):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import (  # pylint: disable=W0611
        ec,  # pylint: disable=W0611
        ed448,  # pylint: disable=W0611
        ed25519,
        mldsa,  # pylint: disable=W0611
        rsa,  # pylint: disable=W0611  # pylint: disable=W0611
    )

    from dns.dnssecalgs import (  # pylint: disable=C0412
        get_algorithm_cls,
        get_algorithm_cls_from_dnskey,
    )
    from dns.dnssecalgs.base import GenericPrivateKey, GenericPublicKey

    validate = _validate  # pyright: ignore
    validate_rrsig = _validate_rrsig  # pyright: ignore
    validate_nsec_negative_proof = _validate_nsec_negative_proof  # pyright: ignore
    validate_nsec_negative_message = _validate_nsec_negative_message  # pyright: ignore
    sign = _sign
    make_dnskey = _make_dnskey
    make_cdnskey = _make_cdnskey
    _have_pyca = True
else:  # pragma: no cover
    validate = _need_pyca
    validate_rrsig = _need_pyca
    validate_nsec_negative_proof = _need_pyca
    validate_nsec_negative_message = _need_pyca
    sign = _need_pyca
    make_dnskey = _need_pyca
    make_cdnskey = _need_pyca
    _have_pyca = False

### BEGIN generated Algorithm constants

RSAMD5 = Algorithm.RSAMD5
DH = Algorithm.DH
DSA = Algorithm.DSA
ECC = Algorithm.ECC
RSASHA1 = Algorithm.RSASHA1
DSANSEC3SHA1 = Algorithm.DSANSEC3SHA1
RSASHA1NSEC3SHA1 = Algorithm.RSASHA1NSEC3SHA1
RSASHA256 = Algorithm.RSASHA256
RSASHA512 = Algorithm.RSASHA512
ECCGOST = Algorithm.ECCGOST
ECDSAP256SHA256 = Algorithm.ECDSAP256SHA256
ECDSAP384SHA384 = Algorithm.ECDSAP384SHA384
ED25519 = Algorithm.ED25519
ED448 = Algorithm.ED448
MLDSA44 = Algorithm.MLDSA44
INDIRECT = Algorithm.INDIRECT
PRIVATEDNS = Algorithm.PRIVATEDNS
PRIVATEOID = Algorithm.PRIVATEOID

### END generated Algorithm constants
