# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import base64

import pytest

import dns.name
import dns.rdatatype
import dns.rrset
import dns.svcbclient
from dns.svcbclient import (
    AliasChainTooLong,
    AliasLoop,
    Status,
    async_resolve_candidates,
    resolve_candidates,
)


def make_query(answers):
    """Make a query function from {(name_text, rdtype_text): [rdata text]}.

    A missing key means NODATA/NXDOMAIN (None is returned).
    """

    def query(name, rdtype):
        key = (name.to_text(), dns.rdatatype.to_text(rdtype))
        rdatas = answers.get(key)
        if rdatas is None:
            return None
        return dns.rrset.from_text(name, 300, "in", key[1], *rdatas)

    return query


def https(name, *rdatas):
    return {(name, "HTTPS"): list(rdatas)}


def test_service_mode_groups_preserve_equal_priority():
    query = make_query(
        https(
            "www.example.",
            "2 b.example. alpn=h2",
            "1 a1.example. alpn=h2",
            "1 a2.example. alpn=h2",
        )
    )
    resolution = resolve_candidates(
        "www.example.", query, alpns=["h2"], resolve_addresses=False
    )
    assert resolution.status is Status.CANDIDATES
    assert [group.priority for group in resolution.groups] == [1, 2]
    # Both priority-1 candidates are retained; no winner is picked.
    targets = {c.target.to_text() for c in resolution.groups[0].candidates}
    assert targets == {"a1.example.", "a2.example."}
    assert len(resolution.groups[1].candidates) == 1
    assert len(resolution.candidates) == 3
    assert resolution.excluded == ()


def test_unsupported_mandatory_skips_record_but_keeps_lower_priority():
    query = make_query(
        https(
            "www.example.",
            "1 fast.example. alpn=h2 mandatory=key65400 key65400=abcd",
            "2 plain.example. alpn=h2",
        )
    )
    resolution = resolve_candidates(
        "www.example.",
        query,
        alpns=["h2"],
        params=["alpn"],
        resolve_addresses=False,
    )
    assert resolution.status is Status.CANDIDATES
    # The priority-1 record is excluded, but the priority-2 candidate
    # remains.
    assert [group.priority for group in resolution.groups] == [2]
    assert resolution.candidates[0].target.to_text() == "plain.example."
    assert len(resolution.excluded) == 1
    assert resolution.excluded[0].rdata.priority == 1
    assert "key65400" in resolution.excluded[0].reason


def test_alias_loop_reports_chain():
    answers = https("a.example.", "0 b.example.")
    answers.update(https("b.example.", "0 a.example."))
    query = make_query(answers)
    with pytest.raises(AliasLoop) as excinfo:
        resolve_candidates("a.example.", query)
    message = str(excinfo.value)
    assert "a.example. -> b.example. -> a.example." in message


def test_alias_chain_too_long():
    answers = {}
    hops = 10
    for i in range(hops + 1):
        answers.update(https(f"n{i}.example.", f"0 n{i + 1}.example."))
    query = make_query(answers)
    with pytest.raises(AliasChainTooLong) as excinfo:
        resolve_candidates("n0.example.", query)
    message = str(excinfo.value)
    assert "n0.example." in message
    assert "n9.example." in message


def test_alias_chain_hop_limit_configurable():
    answers = https("a.example.", "0 b.example.")
    answers.update(https("b.example.", "0 c.example."))
    answers.update(https("c.example.", "1 svc.example. alpn=h2"))
    query = make_query(answers)
    with pytest.raises(AliasChainTooLong):
        resolve_candidates("a.example.", query, max_alias_hops=1)
    resolution = resolve_candidates(
        "a.example.", query, alpns=["h2"], max_alias_hops=2,
        resolve_addresses=False,
    )
    assert resolution.status is Status.CANDIDATES
    assert [n.to_text() for n in resolution.alias_chain] == [
        "a.example.",
        "b.example.",
        "c.example.",
    ]


def test_alias_followed_then_service():
    answers = https("a.example.", "0 b.example.")
    answers.update(https("b.example.", "1 svc.example. alpn=h2 port=8443"))
    query = make_query(answers)
    resolution = resolve_candidates(
        "a.example.", query, alpns=["h2"], resolve_addresses=False
    )
    assert resolution.status is Status.CANDIDATES
    candidate = resolution.candidates[0]
    assert candidate.target.to_text() == "svc.example."
    assert candidate.port == 8443


def test_fallback_when_no_https_data():
    query = make_query({})
    resolution = resolve_candidates("www.example.", query)
    assert resolution.status is Status.FALLBACK
    assert resolution.groups == ()
    assert resolution.excluded == ()


def test_fallback_when_alias_target_has_no_data():
    query = make_query(https("a.example.", "0 b.example."))
    resolution = resolve_candidates("a.example.", query)
    assert resolution.status is Status.FALLBACK
    assert [n.to_text() for n in resolution.alias_chain] == [
        "a.example.",
        "b.example.",
    ]


def test_unavailable_when_root_target():
    query = make_query(https("www.example.", "1 ."))
    resolution = resolve_candidates("www.example.", query)
    assert resolution.status is Status.UNAVAILABLE
    assert resolution.groups == ()
    assert len(resolution.excluded) == 1
    assert "root" in resolution.excluded[0].reason


def test_unavailable_when_all_records_excluded():
    query = make_query(
        https("www.example.", "1 a.example. mandatory=key65400 key65400=abcd")
    )
    resolution = resolve_candidates("www.example.", query)
    # The service published records, so this is not a fallback case.
    assert resolution.status is Status.UNAVAILABLE
    assert resolution.groups == ()


def test_no_default_alpn_and_alpn_intersection():
    query = make_query(
        https("www.example.", "1 a.example. alpn=h3,h2 no-default-alpn")
    )
    resolution = resolve_candidates(
        "www.example.", query, alpns=["h2", "http/1.1"], resolve_addresses=False
    )
    candidate = resolution.candidates[0]
    # The intersection keeps the record's order.
    assert candidate.alpns == (b"h2",)
    assert candidate.no_default_alpn


def test_default_alpn_when_no_alpn_param():
    query = make_query(https("www.example.", "1 a.example."))
    resolution = resolve_candidates(
        "www.example.", query, resolve_addresses=False
    )
    candidate = resolution.candidates[0]
    assert candidate.alpns == ()
    assert not candidate.no_default_alpn


def test_no_common_alpn_excludes():
    query = make_query(https("www.example.", "1 a.example. alpn=h3"))
    resolution = resolve_candidates(
        "www.example.", query, alpns=["h2"], resolve_addresses=False
    )
    assert resolution.status is Status.UNAVAILABLE
    assert "ALPN" in resolution.excluded[0].reason


def test_port_and_ech_passthrough():
    ech = base64.b64encode(b"\x00\x01\x02").decode()
    query = make_query(
        https("www.example.", f"1 a.example. port=8443 ech={ech}")
    )
    resolution = resolve_candidates(
        "www.example.", query, resolve_addresses=False
    )
    candidate = resolution.candidates[0]
    assert candidate.port == 8443
    assert candidate.ech == b"\x00\x01\x02"


def test_hints_distinguished_from_queried_addresses():
    answers = https(
        "www.example.",
        "1 a.example. ipv4hint=192.0.2.1 ipv6hint=2001:db8::1",
    )
    answers[("a.example.", "A")] = ["192.0.2.2"]
    answers[("a.example.", "AAAA")] = ["2001:db8::2"]
    query = make_query(answers)
    resolution = resolve_candidates("www.example.", query)
    candidate = resolution.candidates[0]
    assert candidate.ipv4_hints == ("192.0.2.1",)
    assert candidate.ipv6_hints == ("2001:db8::1",)
    assert candidate.ipv4_addresses == ("192.0.2.2",)
    assert candidate.ipv6_addresses == ("2001:db8::2",)


def test_address_resolution_disabled():
    answers = https("www.example.", "1 a.example. ipv4hint=192.0.2.1")
    answers[("a.example.", "A")] = ["192.0.2.2"]
    query = make_query(answers)
    resolution = resolve_candidates(
        "www.example.", query, resolve_addresses=False
    )
    candidate = resolution.candidates[0]
    assert candidate.ipv4_hints == ("192.0.2.1",)
    assert candidate.ipv4_addresses == ()


def test_async_adapter():
    answers = https("a.example.", "0 b.example.")
    answers.update(https("b.example.", "1 svc.example. alpn=h2"))
    sync_query = make_query(answers)

    async def query(name, rdtype):
        return sync_query(name, rdtype)

    resolution = asyncio.run(
        async_resolve_candidates(
            "a.example.", query, alpns=["h2"], resolve_addresses=False
        )
    )
    assert resolution.status is Status.CANDIDATES
    assert resolution.candidates[0].target.to_text() == "svc.example."
    assert [n.to_text() for n in resolution.alias_chain] == [
        "a.example.",
        "b.example.",
    ]


def test_svcb_rdtype():
    answers = {
        ("_dns.example.", "SVCB"): ["1 svc.example. alpn=doq"],
    }
    query = make_query(answers)
    resolution = resolve_candidates(
        "_dns.example.",
        query,
        rdtype=dns.rdatatype.SVCB,
        alpns=["doq"],
        resolve_addresses=False,
    )
    assert resolution.status is Status.CANDIDATES
    assert resolution.candidates[0].alpns == (b"doq",)
