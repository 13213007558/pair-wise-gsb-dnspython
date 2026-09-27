# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Client-side HTTPS/SVCB service candidate resolution (RFC 9460).

This module implements the client-side selection rules for HTTPS and SVCB
records.  The caller supplies the ALPN protocol identifiers and SvcParamKeys
it supports, along with a query function, and gets back either an ordered
list of candidate groups, an indication that it may fall back to ordinary
address resolution, or an indication that the service is unavailable.

All DNS I/O goes through the caller-supplied query function, so applications
with their own stub resolvers (and tests with controlled RRsets) can plug in
whatever behavior they need.  Both synchronous and asynchronous query
functions are supported; the candidate selection rules are shared.

ECH (encrypted client hello) configurations are passed through opaquely;
this module does not attempt any TLS processing.
"""

import enum
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Iterable

import dns.exception
import dns.name
import dns.rdatatype
import dns.rrset
from dns.rdtypes.svcbbase import ParamKey, key_to_text

#: The default maximum number of AliasMode records followed while resolving
#: a service name.
DEFAULT_MAX_ALIAS_HOPS = 8


class AliasLoop(dns.exception.DNSException):
    """Following AliasMode records led back to an already-visited name.

    The ``chain`` keyword argument is a text rendering of the names
    visited, in order, ending with the name that closes the loop.
    """

    fmt = "HTTPS/SVCB alias loop detected: {chain}"
    supp_kwargs = {"chain"}


class AliasChainTooLong(dns.exception.DNSException):
    """The AliasMode chain exceeded the maximum number of hops.

    The ``chain`` keyword argument is a text rendering of the names
    visited, in order.
    """

    fmt = "HTTPS/SVCB alias chain too long: {chain}"
    supp_kwargs = {"chain"}


class Status(enum.Enum):
    """The outcome of service candidate resolution."""

    #: Usable ServiceMode candidates were found.
    CANDIDATES = 0
    #: No HTTPS/SVCB data exists for the name; the caller may fall back to
    #: ordinary A/AAAA address resolution.
    FALLBACK = 1
    #: The service published HTTPS/SVCB records, but none of them are
    #: usable, or it explicitly said the service is not offered.  The
    #: caller should not treat this as a successful fallback to ordinary
    #: address resolution.
    UNAVAILABLE = 2


@dataclass
class Candidate:
    """A single usable ServiceMode candidate.

    The ``alpns`` field is the tuple of ALPN protocol identifiers (as
    ``bytes``) from the record's alpn parameter that the caller also
    supports, in the record's order.  It is empty if the record has no
    alpn parameter, in which case the default ALPN for the service is
    used.  If ``no_default_alpn`` is True, the caller must not use the
    default ALPN with this candidate.

    ``port`` is the explicit port from the record's port parameter, or
    None if the default port for the service applies.

    ``ech`` is the ECH configuration from the record, passed through
    opaquely as ``bytes``, or None.

    ``ipv4_hints`` and ``ipv6_hints`` are the address hints from the
    record; they are only hints.  ``ipv4_addresses`` and
    ``ipv6_addresses`` are addresses obtained from independent A/AAAA
    queries for the target name (empty if address resolution was
    disabled or returned nothing).

    ``rdata`` is the source rdata, for access to any parameters not
    interpreted here.
    """

    priority: int
    target: dns.name.Name
    alpns: tuple
    no_default_alpn: bool
    port: int | None
    ech: bytes | None
    ipv4_hints: tuple
    ipv6_hints: tuple
    rdata: Any
    ipv4_addresses: tuple = ()
    ipv6_addresses: tuple = ()


@dataclass(frozen=True)
class Excluded:
    """A ServiceMode record that was not usable, with the reason why."""

    rdata: Any
    reason: str


@dataclass(frozen=True)
class CandidateGroup:
    """The usable candidates at one SvcPriority.

    All candidates in a group are equivalent; no winner has been picked.
    """

    priority: int
    candidates: tuple


@dataclass(frozen=True)
class Resolution:
    """The result of resolving a service name into candidates.

    ``name`` is the original name resolved, and ``alias_chain`` is the
    tuple of names visited while following AliasMode records, starting
    with ``name``.  ``groups`` is a tuple of ``CandidateGroup`` sorted by
    ascending priority.  ``excluded`` is a tuple of ``Excluded``
    explaining why particular records were not usable.
    """

    name: dns.name.Name
    status: Status
    groups: tuple
    excluded: tuple
    alias_chain: tuple

    @property
    def candidates(self) -> tuple:
        """All candidates, flattened in priority order."""
        return tuple(c for group in self.groups for c in group.candidates)


#: A synchronous query function.  It is called with a ``dns.name.Name``
#: and a ``dns.rdatatype.RdataType``, and returns the answer
#: ``dns.rrset.RRset``, or None if there is no such data (e.g. NODATA or
#: NXDOMAIN).
QueryFunction = Callable[
    [dns.name.Name, dns.rdatatype.RdataType], dns.rrset.RRset | None
]

#: An asynchronous query function; like ``QueryFunction`` but awaited.
AsyncQueryFunction = Callable[
    [dns.name.Name, dns.rdatatype.RdataType],
    Awaitable[dns.rrset.RRset | None],
]


def _normalize_alpns(alpns: Iterable[str | bytes]) -> tuple:
    normalized = []
    for alpn in alpns:
        if isinstance(alpn, str):
            alpn = alpn.encode()
        normalized.append(bytes(alpn))
    return tuple(normalized)


def _normalize_params(params: Iterable[int | str | ParamKey]) -> tuple:
    return tuple(ParamKey.make(p) for p in params)


def _make_groups(candidates: list) -> tuple:
    by_priority: dict = {}
    for candidate in candidates:
        by_priority.setdefault(candidate.priority, []).append(candidate)
    return tuple(
        CandidateGroup(priority, tuple(by_priority[priority]))
        for priority in sorted(by_priority)
    )


class _Core:
    """The I/O-independent HTTPS/SVCB resolution state machine."""

    def __init__(self, name, supported_params, supported_alpns, max_alias_hops):
        self.start_name = name
        self.current_name = name
        self.chain = [name]
        self.supported_params = supported_params
        self.supported_alpns = supported_alpns
        self.max_alias_hops = max_alias_hops

    def _chain_text(self, extra=None):
        names = list(self.chain)
        if extra is not None:
            names.append(extra)
        return " -> ".join(n.to_text() for n in names)

    def process_rrset(self, rrset):
        """Process the RRset (or None) obtained for the current name.

        Returns a ``Resolution`` if resolution is complete, or None if
        another query for ``self.current_name`` (which will have been
        updated) is needed.
        """
        if rrset is None:
            return Resolution(
                self.start_name, Status.FALLBACK, (), (), tuple(self.chain)
            )
        aliases = []
        services = []
        for rd in rrset:
            if rd.priority == 0:
                aliases.append(rd)
            else:
                services.append(rd)
        excluded = []
        if aliases:
            # AliasMode records take precedence over any ServiceMode
            # records in the same RRset (a mixed RRset is a
            # misconfiguration).  SvcParams on AliasMode records are
            # ignored, per RFC 9460.
            target = None
            for rd in aliases:
                if rd.target == dns.name.root:
                    excluded.append(Excluded(rd, "AliasMode record with root target"))
                elif target is None:
                    target = rd.target
            if target is not None:
                if target in self.chain:
                    raise AliasLoop(chain=self._chain_text(target))
                if len(self.chain) > self.max_alias_hops:
                    raise AliasChainTooLong(chain=self._chain_text(target))
                self.chain.append(target)
                self.current_name = target
                return None
        candidates = []
        for rd in services:
            candidate = self._candidate_from_rdata(rd, excluded)
            if candidate is not None:
                candidates.append(candidate)
        if candidates:
            groups = _make_groups(candidates)
            status = Status.CANDIDATES
        else:
            groups = ()
            status = Status.UNAVAILABLE
        return Resolution(
            self.start_name, status, groups, tuple(excluded), tuple(self.chain)
        )

    def _candidate_from_rdata(self, rd, excluded):
        params = rd.params
        mandatory = params.get(ParamKey.MANDATORY)
        if mandatory is not None:
            for key in mandatory.keys:
                if key not in self.supported_params:
                    excluded.append(
                        Excluded(
                            rd,
                            f"mandatory parameter {key_to_text(key)} not supported",
                        )
                    )
                    return None
        alpn_param = params.get(ParamKey.ALPN)
        if alpn_param is not None:
            alpns = tuple(
                alpn for alpn in alpn_param.ids if alpn in self.supported_alpns
            )
            if not alpns:
                excluded.append(
                    Excluded(rd, "no ALPN in common with the supported ALPNs")
                )
                return None
        else:
            alpns = ()
        if rd.target == dns.name.root:
            excluded.append(
                Excluded(rd, "service not offered (TargetName is the root)")
            )
            return None
        port_param = params.get(ParamKey.PORT)
        port = port_param.port if port_param is not None else None
        ech_param = params.get(ParamKey.ECH)
        ech = ech_param.ech if ech_param is not None else None
        ipv4_hint = params.get(ParamKey.IPV4HINT)
        ipv6_hint = params.get(ParamKey.IPV6HINT)
        return Candidate(
            priority=rd.priority,
            target=rd.target,
            alpns=alpns,
            no_default_alpn=ParamKey.NO_DEFAULT_ALPN in params,
            port=port,
            ech=ech,
            ipv4_hints=tuple(ipv4_hint.addresses) if ipv4_hint is not None else (),
            ipv6_hints=tuple(ipv6_hint.addresses) if ipv6_hint is not None else (),
            rdata=rd,
        )


def _address_targets(resolution: Resolution) -> list:
    targets = []
    for group in resolution.groups:
        for candidate in group.candidates:
            if candidate.target not in targets:
                targets.append(candidate.target)
    return targets


def _extract_addresses(rrset) -> tuple:
    if rrset is None:
        return ()
    return tuple(rd.address for rd in rrset)


def _apply_addresses(resolution: Resolution, addresses: dict) -> None:
    for group in resolution.groups:
        for candidate in group.candidates:
            ipv4, ipv6 = addresses.get(candidate.target, ((), ()))
            candidate.ipv4_addresses = ipv4
            candidate.ipv6_addresses = ipv6


def _make_core(name, alpns, params, max_alias_hops):
    if isinstance(name, str):
        name = dns.name.from_text(name)
    return _Core(
        name, _normalize_params(params), _normalize_alpns(alpns), max_alias_hops
    )


def resolve_candidates(
    name: dns.name.Name | str,
    query: QueryFunction,
    *,
    rdtype: dns.rdatatype.RdataType = dns.rdatatype.HTTPS,
    alpns: Iterable[str | bytes] = (),
    params: Iterable[int | str | ParamKey] = (),
    max_alias_hops: int = DEFAULT_MAX_ALIAS_HOPS,
    resolve_addresses: bool = True,
) -> Resolution:
    """Resolve a service name into HTTPS/SVCB candidates, synchronously.

    ``name`` is the service name.  ``query`` is a ``QueryFunction`` used
    for all queries.  ``rdtype`` is the service rdata type, defaulting to
    HTTPS; SVCB may be used for other schemes.  ``alpns`` is the
    caller-supported ALPN protocol identifiers.  ``params`` is the
    caller-supported SvcParamKeys; records mandating anything else are
    excluded.  ``max_alias_hops`` limits the AliasMode chain length.  If
    ``resolve_addresses`` is True (the default), A and AAAA queries are
    made for candidate targets and reported separately from the address
    hints in the records.

    Returns a ``Resolution``.  Raises ``AliasLoop`` or
    ``AliasChainTooLong`` for malformed alias chains.
    """
    core = _make_core(name, alpns, params, max_alias_hops)
    while True:
        rrset = query(core.current_name, rdtype)
        resolution = core.process_rrset(rrset)
        if resolution is not None:
            break
    if resolve_addresses:
        addresses = {}
        for target in _address_targets(resolution):
            ipv4 = _extract_addresses(query(target, dns.rdatatype.A))
            ipv6 = _extract_addresses(query(target, dns.rdatatype.AAAA))
            addresses[target] = (ipv4, ipv6)
        _apply_addresses(resolution, addresses)
    return resolution


async def async_resolve_candidates(
    name: dns.name.Name | str,
    query: AsyncQueryFunction,
    *,
    rdtype: dns.rdatatype.RdataType = dns.rdatatype.HTTPS,
    alpns: Iterable[str | bytes] = (),
    params: Iterable[int | str | ParamKey] = (),
    max_alias_hops: int = DEFAULT_MAX_ALIAS_HOPS,
    resolve_addresses: bool = True,
) -> Resolution:
    """Resolve a service name into HTTPS/SVCB candidates, asynchronously.

    This is identical to ``resolve_candidates()`` except that ``query``
    is an ``AsyncQueryFunction`` and is awaited.
    """
    core = _make_core(name, alpns, params, max_alias_hops)
    while True:
        rrset = await query(core.current_name, rdtype)
        resolution = core.process_rrset(rrset)
        if resolution is not None:
            break
    if resolve_addresses:
        addresses = {}
        for target in _address_targets(resolution):
            ipv4 = _extract_addresses(await query(target, dns.rdatatype.A))
            ipv6 = _extract_addresses(await query(target, dns.rdatatype.AAAA))
            addresses[target] = (ipv4, ipv6)
        _apply_addresses(resolution, addresses)
    return resolution
