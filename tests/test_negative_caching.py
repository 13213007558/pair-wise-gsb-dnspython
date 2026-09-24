# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

"""Tests for resolver negative caching (NXDOMAIN and NODATA)."""

import threading
import time
import unittest.mock

import pytest

import dns.message
import dns.name
import dns.nameserver
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset

EXAMPLE = dns.name.from_text("example.")
NX_EXAMPLE = dns.name.from_text("nx.example.")
WWW_EXAMPLE = dns.name.from_text("www.example.")
SOA_TTL = 100
SOA_MINIMUM = 50
# The RFC 2308 negative caching TTL is min(SOA TTL, SOA minimum).
NEGATIVE_TTL = min(SOA_TTL, SOA_MINIMUM)


def nxdomain_key(qname):
    # NXDOMAIN entries are cached by qname only, using the NXNAME
    # meta-type so they cannot collide with any (qname, qtype, qclass)
    # key of a NODATA or positive entry.
    return (qname, dns.rdatatype.NXNAME, dns.rdataclass.IN)


def nodata_key(qname, qtype):
    return (qname, dns.rdatatype.RdataType.make(qtype), dns.rdataclass.IN)


class InMemoryNameserver(dns.nameserver.Nameserver):
    """An in-memory nameserver serving a modifiable set of records.

    NXDOMAIN is returned for unknown names and NODATA (NOERROR with an
    empty answer section) for known names without the queried type, both
    with an SOA record in the authority section.  CNAME records are
    chained within the served data.
    """

    def __init__(self, soa_ttl=SOA_TTL, soa_minimum=SOA_MINIMUM):
        super().__init__()
        self.soa_ttl = soa_ttl
        self.soa_minimum = soa_minimum
        self.records = {}
        self.queries = []
        self.extra_authority = []
        self.fail_with_servfail = False
        self.lock = threading.Lock()

    def __str__(self):
        return "in-memory"

    def kind(self):
        return "in-memory"

    def is_always_max_size(self):
        return False

    def answer_nameserver(self):
        return "10.0.0.53"

    def answer_port(self):
        return 53

    def add(self, owner, ttl, rdtype, *rdatas):
        name = dns.name.from_text(owner)
        rrset = dns.rrset.from_text(name, ttl, "IN", rdtype, *rdatas)
        key = (name, dns.rdatatype.RdataType.make(rdtype))
        with self.lock:
            self.records[key] = rrset

    def remove(self, owner, rdtype):
        name = dns.name.from_text(owner)
        key = (name, dns.rdatatype.RdataType.make(rdtype))
        with self.lock:
            del self.records[key]

    def query_count(self):
        with self.lock:
            return len(self.queries)

    def _soa(self):
        return dns.rrset.from_text(
            EXAMPLE,
            self.soa_ttl,
            "IN",
            "SOA",
            f"ns.example. hostmaster.example. 1 3600 600 86400 {self.soa_minimum}",
        )

    def query(
        self, request, timeout, source=None, source_port=0, max_size=False, **kwargs
    ):
        question = request.question[0]
        with self.lock:
            self.queries.append((question.name, question.rdtype))
            records = dict(self.records)
            fail_with_servfail = self.fail_with_servfail
            extra_authority = list(self.extra_authority)
        response = dns.message.make_response(request)
        if fail_with_servfail:
            response.set_rcode(dns.rcode.SERVFAIL)
            return response
        qname = question.name
        qtype = question.rdtype
        found = False
        for _ in range(10):
            rrset = records.get((qname, qtype))
            if rrset is not None:
                response.answer.append(rrset)
                found = True
                break
            cname = records.get((qname, dns.rdatatype.CNAME))
            if cname is not None and qtype != dns.rdatatype.CNAME:
                response.answer.append(cname)
                qname = cname[0].target
                continue
            break
        if not found:
            exists = any(owner == qname for owner, _ in records)
            response.authority.append(self._soa())
            response.authority.extend(extra_authority)
            if not exists:
                response.set_rcode(dns.rcode.NXDOMAIN)
        # Round-trip through the wire format so the response is
        # indistinguishable from one received over the network.
        return dns.message.from_wire(response.to_wire())


def make_resolver(nameserver, cache=None):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    if cache is None:
        cache = dns.resolver.Cache()
    resolver.cache = cache
    return resolver


@pytest.fixture
def clock():
    with unittest.mock.patch("time.time") as mock_time:
        mock_time.return_value = 1_000_000.0
        yield mock_time


def test_nxdomain_is_cached_by_qname_for_all_qtypes():
    nameserver = InMemoryNameserver()
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("nx.example.", "A")
    assert nameserver.query_count() == 1
    # An NXDOMAIN applies to the name, not just to the original qtype.
    for qtype in ["TXT", "AAAA", "MX"]:
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve("nx.example.", qtype)
    assert nameserver.query_count() == 1
    assert resolver.cache.hits() == 3


def test_nxdomain_cache_hit_matches_network_exception():
    nameserver = InMemoryNameserver()
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NXDOMAIN) as network_exc:
        resolver.resolve("nx.example.", "A")
    with pytest.raises(dns.resolver.NXDOMAIN) as cached_exc:
        resolver.resolve("nx.example.", "TXT")
    assert nameserver.query_count() == 1
    network = network_exc.value
    cached = cached_exc.value
    assert cached.qnames() == network.qnames()
    assert set(cached.responses()) == set(network.responses())
    response = cached.response(NX_EXAMPLE)
    assert response is network.response(NX_EXAMPLE)
    assert response.rcode() == dns.rcode.NXDOMAIN


def test_nodata_is_cached_by_qtype_and_qclass():
    nameserver = InMemoryNameserver()
    nameserver.add("www.example.", 300, "A", "10.0.0.1")
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NoAnswer):
        resolver.resolve("www.example.", "AAAA")
    assert nameserver.query_count() == 1
    # The NODATA entry is specific to (qname, qtype, qclass) and does
    # not affect other types.
    answer = resolver.resolve("www.example.", "A")
    assert answer.rrset is not None
    assert nameserver.query_count() == 2
    # A repeated AAAA query is served from the cache.
    with pytest.raises(dns.resolver.NoAnswer):
        resolver.resolve("www.example.", "AAAA")
    assert nameserver.query_count() == 2
    assert resolver.cache.hits() == 1


def test_nxdomain_and_nodata_do_not_share_a_key():
    nameserver = InMemoryNameserver()
    nameserver.add("www.example.", 300, "A", "10.0.0.1")
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("nx.example.", "A")
    with pytest.raises(dns.resolver.NoAnswer):
        resolver.resolve("www.example.", "AAAA")
    # NXDOMAIN is cached by qname (NXNAME meta-type), NODATA by
    # (qname, qtype, qclass); neither uses the other's key or the ANY
    # key.
    assert nxdomain_key(NX_EXAMPLE) in resolver.cache.data
    assert nodata_key(WWW_EXAMPLE, "AAAA") in resolver.cache.data
    assert nodata_key(NX_EXAMPLE, "A") not in resolver.cache.data
    assert nxdomain_key(WWW_EXAMPLE) not in resolver.cache.data
    assert (NX_EXAMPLE, dns.rdatatype.ANY, dns.rdataclass.IN) not in resolver.cache.data
    assert len(resolver.cache.data) == 2


def test_nodata_expires_and_new_record_is_found(clock):
    nameserver = InMemoryNameserver()
    nameserver.add("www.example.", 300, "A", "10.0.0.1")
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NoAnswer):
        resolver.resolve("www.example.", "AAAA")
    key = nodata_key(WWW_EXAMPLE, "AAAA")
    remaining = resolver.cache.data[key].expiration - time.time()
    assert remaining == NEGATIVE_TTL
    # Just before expiry the NODATA entry is still used.
    clock.return_value += NEGATIVE_TTL - 1
    with pytest.raises(dns.resolver.NoAnswer):
        resolver.resolve("www.example.", "AAAA")
    assert nameserver.query_count() == 1
    # After expiry the nameserver is asked again, and the newly added
    # record is returned.
    nameserver.add("www.example.", 300, "AAAA", "2001:db8::1")
    clock.return_value += 2
    answer = resolver.resolve("www.example.", "AAAA")
    assert answer.rrset is not None
    assert answer[0].address == "2001:db8::1"
    assert nameserver.query_count() == 2


def test_nxdomain_expires_and_new_record_is_found(clock):
    nameserver = InMemoryNameserver()
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("nx.example.", "A")
    key = nxdomain_key(NX_EXAMPLE)
    remaining = resolver.cache.data[key].expiration - time.time()
    assert remaining == NEGATIVE_TTL
    clock.return_value += NEGATIVE_TTL + 1
    nameserver.add("nx.example.", 300, "A", "10.0.0.9")
    answer = resolver.resolve("nx.example.", "A")
    assert answer.rrset is not None
    assert answer[0].address == "10.0.0.9"
    assert nameserver.query_count() == 2


def test_cname_chain_to_nxdomain_uses_chain_and_soa_ttl(clock):
    nameserver = InMemoryNameserver()
    nameserver.add("www.example.", 30, "CNAME", "target.example.")
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("www.example.", "A")
    key = nxdomain_key(WWW_EXAMPLE)
    remaining = resolver.cache.data[key].expiration - time.time()
    # min(CNAME TTL 30, SOA TTL 100, SOA minimum 50)
    assert remaining == 30
    # The cached NXDOMAIN covers other qtypes too.
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("www.example.", "AAAA")
    assert nameserver.query_count() == 1


def test_cname_chain_to_nodata_uses_chain_and_soa_ttl(clock):
    nameserver = InMemoryNameserver()
    nameserver.add("www.example.", 30, "CNAME", "target.example.")
    nameserver.add("target.example.", 60, "A", "10.0.0.2")
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NoAnswer):
        resolver.resolve("www.example.", "AAAA")
    key = nodata_key(WWW_EXAMPLE, "AAAA")
    remaining = resolver.cache.data[key].expiration - time.time()
    # min(CNAME TTL 30, SOA TTL 100, SOA minimum 50)
    assert remaining == 30


def test_nsec_ttl_does_not_change_negative_ttl(clock):
    nameserver = InMemoryNameserver()
    # DNSSEC authenticated denial of existence adds NSEC records to the
    # authority section; their TTLs must not be mixed into the negative
    # caching TTL, which comes from the SOA alone.
    nameserver.extra_authority.append(
        dns.rrset.from_text(EXAMPLE, 10000, "IN", "NSEC", "a.example. A SOA RRSIG NSEC")
    )
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("nx.example.", "A")
    key = nxdomain_key(NX_EXAMPLE)
    remaining = resolver.cache.data[key].expiration - time.time()
    assert remaining == NEGATIVE_TTL


def test_nodata_cache_hit_matches_network_exception():
    nameserver = InMemoryNameserver()
    nameserver.add("www.example.", 300, "A", "10.0.0.1")
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NoAnswer) as network_exc:
        resolver.resolve("www.example.", "AAAA")
    with pytest.raises(dns.resolver.NoAnswer) as cached_exc:
        resolver.resolve("www.example.", "AAAA")
    assert nameserver.query_count() == 1
    assert cached_exc.value.response() is network_exc.value.response()


def test_nodata_cache_hit_with_raise_on_no_answer_false():
    nameserver = InMemoryNameserver()
    nameserver.add("www.example.", 300, "A", "10.0.0.1")
    resolver = make_resolver(nameserver)
    network_answer = resolver.resolve("www.example.", "AAAA", raise_on_no_answer=False)
    assert network_answer.rrset is None
    cached_answer = resolver.resolve("www.example.", "AAAA", raise_on_no_answer=False)
    assert nameserver.query_count() == 1
    assert cached_answer.rrset is None
    assert cached_answer.response is network_answer.response


def test_flush_clears_negative_entries():
    for cache in [dns.resolver.Cache(), dns.resolver.LRUCache(100)]:
        nameserver = InMemoryNameserver()
        resolver = make_resolver(nameserver, cache)
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve("nx.example.", "A")
        cache.flush()
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve("nx.example.", "A")
        assert nameserver.query_count() == 2


def test_failed_query_leaves_no_cache_entry():
    nameserver = InMemoryNameserver()
    nameserver.fail_with_servfail = True
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NoNameservers):
        resolver.resolve("nx.example.", "A")
    assert resolver.cache.data == {}


def test_failed_refresh_after_expiry_leaves_no_entry(clock):
    nameserver = InMemoryNameserver()
    resolver = make_resolver(nameserver)
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("nx.example.", "A")
    key = nxdomain_key(NX_EXAMPLE)
    assert key in resolver.cache.data
    clock.return_value += NEGATIVE_TTL + 1
    nameserver.fail_with_servfail = True
    with pytest.raises(dns.resolver.NoNameservers):
        resolver.resolve("nx.example.", "A")
    # The failed query did not leave a usable entry behind.
    assert resolver.cache.get(key) is None


def test_concurrent_resolution_caches_a_single_entry():
    nameserver = InMemoryNameserver()
    resolver = make_resolver(nameserver)
    outcomes = []

    def worker():
        try:
            resolver.resolve("nx.example.", "A")
            outcomes.append("no exception")  # pragma: no cover
        except dns.resolver.NXDOMAIN:
            outcomes.append("NXDOMAIN")
        except Exception as e:  # pragma: no cover
            outcomes.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes == ["NXDOMAIN"] * 8
    # Concurrent fillers left exactly one consistent entry behind.
    assert list(resolver.cache.data.keys()) == [nxdomain_key(NX_EXAMPLE)]
    statistics = resolver.cache.get_statistics_snapshot()
    assert statistics.hits + statistics.misses >= 8


def test_search_list_entries_are_cached_separately():
    nameserver = InMemoryNameserver()
    nameserver.add("foo.example.org.", 300, "A", "10.0.0.5")
    resolver = make_resolver(nameserver)
    resolver.search = [
        dns.name.from_text("example.com"),
        dns.name.from_text("example.org"),
    ]
    answer = resolver.resolve("foo", "A", search=True)
    assert answer.rrset is not None
    assert answer[0].address == "10.0.0.5"
    assert nameserver.query_count() == 2
    # The NXDOMAIN for foo.example.com is cached and does not leak into
    # the foo.example.org result; a repeated resolution is fully cached.
    answer = resolver.resolve("foo", "A", search=True)
    assert answer.rrset is not None
    assert nameserver.query_count() == 2
    # The NXDOMAIN for foo.example.com does not affect an explicit
    # query for foo.example.org.
    answer = resolver.resolve("foo.example.org.", "A")
    assert answer.rrset is not None
    assert nameserver.query_count() == 2


def test_lru_cache_also_caches_negative_entries():
    nameserver = InMemoryNameserver()
    nameserver.add("www.example.", 300, "A", "10.0.0.1")
    resolver = make_resolver(nameserver, dns.resolver.LRUCache(10))
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("nx.example.", "A")
    with pytest.raises(dns.resolver.NXDOMAIN):
        resolver.resolve("nx.example.", "TXT")
    with pytest.raises(dns.resolver.NoAnswer):
        resolver.resolve("www.example.", "AAAA")
    with pytest.raises(dns.resolver.NoAnswer):
        resolver.resolve("www.example.", "AAAA")
    assert nameserver.query_count() == 2


def test_nxname_is_not_a_valid_query_type():
    # The NXNAME meta-type used for NXDOMAIN cache keys can never be
    # used by a real query, so negative and positive key spaces are
    # disjoint.
    resolver = make_resolver(InMemoryNameserver())
    with pytest.raises(dns.resolver.NoMetaqueries):
        resolver.resolve("www.example.", "NXNAME")
