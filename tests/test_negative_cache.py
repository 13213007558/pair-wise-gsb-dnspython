"""Tests for resolver negative caching (NXDOMAIN and NODATA)."""

import threading
import time

import pytest

import dns.flags
import dns.name
import dns.nameserver
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
from tests.test_resolver import FakeTime

ORIGIN = dns.name.from_text("example.")
NX_NAME = dns.name.from_text("nx.example.")
HOST_NAME = dns.name.from_text("host.example.")


class InMemoryNameserver(dns.nameserver.Nameserver):
    """An in-memory authoritative nameserver.

    Records can be added between queries, and the server counts the
    queries it receives so tests can verify cache hits.
    """

    def __init__(self, *, soa_ttl=300, soa_minimum=5, send_soa=True, delay=0):
        super().__init__()
        self.soa_ttl = soa_ttl
        self.soa_minimum = soa_minimum
        self.send_soa = send_soa
        self.delay = delay
        self.records = {}  # name -> {rdtype: rrset}
        self.empty_names = set()  # empty non-terminals
        self.queries = []
        self.fail = False
        self.lock = threading.Lock()

    def __str__(self):
        return "in-memory"

    def kind(self):
        return "in-memory"

    def is_always_max_size(self):
        return False

    def answer_nameserver(self):
        return "in-memory"

    def answer_port(self):
        return 53

    def add_record(self, name, rdtype, *rdatas, ttl=300):
        name = dns.name.from_text(name)
        rrset = dns.rrset.from_text(name, ttl, "IN", rdtype, *rdatas)
        with self.lock:
            self.records.setdefault(name, {})[rrset.rdtype] = rrset

    def query_count(self):
        with self.lock:
            return len(self.queries)

    def _add_soa(self, response, qname):
        if not self.send_soa:
            return
        # The SOA owner name must be a superdomain of the qname.
        if qname.is_subdomain(ORIGIN):
            origin = ORIGIN
        else:
            origin = dns.name.root
        soa = dns.rrset.from_text(
            origin,
            self.soa_ttl,
            "IN",
            "SOA",
            f"ns.example. root.example. 1 2 3 4 {self.soa_minimum}",
        )
        self._add_rrset(response, response.authority, soa)

    @staticmethod
    def _add_rrset(response, section, rrset):
        # We have to add via find_rrset() so that the message's index
        # stays in sync with the section.
        target = response.find_rrset(
            section, rrset.name, rrset.rdclass, rrset.rdtype, create=True
        )
        for rdata in rrset:
            target.add(rdata, rrset.ttl)

    def query(
        self,
        request,
        timeout,
        source=None,
        source_port=0,
        max_size=False,
        one_rr_per_rrset=False,
        ignore_trailing=False,
    ):
        if self.delay:
            time.sleep(self.delay)
        with self.lock:
            question = request.question[0]
            self.queries.append((question.name, question.rdtype))
            response = dns.message.make_response(request)
            response.flags |= dns.flags.RA | dns.flags.AA
            if self.fail:
                response.set_rcode(dns.rcode.SERVFAIL)
                return response
            qname = question.name
            qtype = question.rdtype
            types = self.records.get(qname, {})
            if qtype in types:
                self._add_rrset(response, response.answer, types[qtype])
                response.set_rcode(dns.rcode.NOERROR)
                return response
            cname = types.get(dns.rdatatype.CNAME)
            if cname is not None and qtype != dns.rdatatype.CNAME:
                self._add_rrset(response, response.answer, cname)
                target = cname[0].target
                target_types = self.records.get(target, {})
                if qtype in target_types:
                    self._add_rrset(response, response.answer, target_types[qtype])
                    response.set_rcode(dns.rcode.NOERROR)
                elif target_types or target in self.empty_names:
                    # NODATA at the target of the chain.
                    response.set_rcode(dns.rcode.NOERROR)
                    self._add_soa(response, qname)
                else:
                    # NXDOMAIN at the target of the chain.
                    response.set_rcode(dns.rcode.NXDOMAIN)
                    self._add_soa(response, qname)
                return response
            if types or qname in self.empty_names:
                # The name exists, but not with the wanted type (NODATA).
                response.set_rcode(dns.rcode.NOERROR)
                self._add_soa(response, qname)
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
                self._add_soa(response, qname)
            return response


def make_resolver(server, **kwargs):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.cache = dns.resolver.Cache()
    for key, value in kwargs.items():
        setattr(resolver, key, value)
    return resolver


def test_nxdomain_is_cached_by_qname():
    server = InMemoryNameserver()
    with FakeTime():
        resolver = make_resolver(server)
        with pytest.raises(dns.resolver.NXDOMAIN) as excinfo:
            resolver.resolve(NX_NAME, "A")
        assert server.query_count() == 1
        # The exception has the same metadata as a network NXDOMAIN.
        assert excinfo.value.qnames() == [NX_NAME]
        response = excinfo.value.responses()[NX_NAME]
        assert response.rcode() == dns.rcode.NXDOMAIN
        # A repeat query is a cache hit, and raises the same exception
        # type with the same response metadata.
        with pytest.raises(dns.resolver.NXDOMAIN) as excinfo:
            resolver.resolve(NX_NAME, "A")
        assert server.query_count() == 1
        assert excinfo.value.responses()[NX_NAME].rcode() == dns.rcode.NXDOMAIN
        # An NXDOMAIN is cached by qname, so it covers all qtypes.
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "AAAA")
        assert server.query_count() == 1
        assert resolver.cache.hits() == 2


def test_nxdomain_uses_soa_negative_ttl():
    server = InMemoryNameserver(soa_ttl=300, soa_minimum=5)
    with FakeTime() as now:
        resolver = make_resolver(server)
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "A")
        key = (NX_NAME, dns.rdatatype.ANY, dns.rdataclass.IN)
        answer = resolver.cache.data[key]
        # The negative TTL is min(SOA TTL, SOA MINIMUM), and the
        # remaining TTL decreases on the same clock.
        assert answer.expiration - now.time() == 5
        now.sleep(4)
        assert answer.expiration - now.time() == 1
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "A")
        assert server.query_count() == 1
        # After the negative TTL expires, the name is queried again.
        now.sleep(2)
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "A")
        assert server.query_count() == 2
        assert resolver.cache.data[key].expiration - now.time() == 5


def test_nodata_is_cached_by_qtype_and_qclass():
    server = InMemoryNameserver()
    server.add_record("host.example.", "A", "10.0.0.1")
    with FakeTime():
        resolver = make_resolver(server)
        with pytest.raises(dns.resolver.NoAnswer) as excinfo:
            resolver.resolve(HOST_NAME, "AAAA")
        assert server.query_count() == 1
        # The cache hit raises the same exception type with the same
        # response metadata as the network query.
        assert excinfo.value.response().rcode() == dns.rcode.NOERROR
        # A repeat query is a cache hit.
        with pytest.raises(dns.resolver.NoAnswer):
            resolver.resolve(HOST_NAME, "AAAA")
        assert server.query_count() == 1
        # The NODATA for AAAA does not block other qtypes.
        answer = resolver.resolve(HOST_NAME, "A")
        assert answer[0].address == "10.0.0.1"
        assert server.query_count() == 2


def test_nodata_expires_and_new_record_is_found():
    server = InMemoryNameserver(soa_ttl=300, soa_minimum=5)
    server.add_record("host.example.", "A", "10.0.0.1")
    with FakeTime() as now:
        resolver = make_resolver(server)
        with pytest.raises(dns.resolver.NoAnswer):
            resolver.resolve(HOST_NAME, "AAAA")
        assert server.query_count() == 1
        # The domain adds an AAAA record.
        server.add_record("host.example.", "AAAA", "fd00::1")
        # The old NODATA is still cached until its TTL expires.
        with pytest.raises(dns.resolver.NoAnswer):
            resolver.resolve(HOST_NAME, "AAAA")
        assert server.query_count() == 1
        # After the SOA negative TTL, the new record is found.
        now.sleep(6)
        answer = resolver.resolve(HOST_NAME, "AAAA")
        assert answer[0].address == "fd00::1"
        assert server.query_count() == 2


def test_negative_answer_without_soa_is_not_cached():
    server = InMemoryNameserver(send_soa=False)
    with FakeTime():
        resolver = make_resolver(server)
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "A")
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "A")
        assert server.query_count() == 2
        server.add_record("host.example.", "A", "10.0.0.1")
        with pytest.raises(dns.resolver.NoAnswer):
            resolver.resolve(HOST_NAME, "AAAA")
        with pytest.raises(dns.resolver.NoAnswer):
            resolver.resolve(HOST_NAME, "AAAA")
        assert server.query_count() == 4


def test_cname_chain_nxdomain_uses_soa_negative_ttl():
    server = InMemoryNameserver(soa_ttl=300, soa_minimum=60)
    # The CNAME's TTL is shorter than the SOA negative TTL; the chain
    # and negative expiration rules must not be mixed.
    server.add_record("www.example.", "CNAME", "alias.example.", ttl=10)
    with FakeTime() as now:
        resolver = make_resolver(server)
        with pytest.raises(dns.resolver.NXDOMAIN) as excinfo:
            resolver.resolve("www.example.", "A")
        assert excinfo.value.canonical_name == dns.name.from_text("alias.example.")
        key = (
            dns.name.from_text("www.example."),
            dns.rdatatype.ANY,
            dns.rdataclass.IN,
        )
        answer = resolver.cache.data[key]
        assert answer.expiration - now.time() == 60


def test_cname_chain_positive_answer_uses_chain_minimum_ttl():
    server = InMemoryNameserver()
    server.add_record("www.example.", "CNAME", "host.example.", ttl=10)
    server.add_record("host.example.", "A", "10.0.0.1", ttl=300)
    with FakeTime() as now:
        resolver = make_resolver(server)
        answer = resolver.resolve("www.example.", "A")
        assert answer[0].address == "10.0.0.1"
        assert answer.expiration - now.time() == 10


def test_concurrent_resolves_have_a_single_filler():
    server = InMemoryNameserver(delay=0.2)
    server.add_record("host.example.", "A", "10.0.0.1")
    resolver = make_resolver(server)
    barrier = threading.Barrier(8)
    results = []
    errors = []

    def worker():
        try:
            barrier.wait()
            results.append(resolver.resolve(HOST_NAME, "A"))
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert not errors
    assert len(results) == 8
    # Only one of the threads queried the nameserver; the rest got
    # the answer from the cache.
    assert server.query_count() == 1
    assert resolver.cache.hits() >= 1
    for answer in results:
        assert answer[0].address == "10.0.0.1"


def test_concurrent_nxdomain_resolves_have_a_single_filler():
    server = InMemoryNameserver(delay=0.2)
    resolver = make_resolver(server)
    barrier = threading.Barrier(8)
    errors = []

    def worker():
        try:
            barrier.wait()
            resolver.resolve(NX_NAME, "A")
        except dns.resolver.NXDOMAIN as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(errors) == 8
    assert server.query_count() == 1


def test_failed_query_after_expiration_leaves_no_partial_entry():
    server = InMemoryNameserver(soa_ttl=300, soa_minimum=5)
    server.add_record("host.example.", "A", "10.0.0.1", ttl=5)
    with FakeTime() as now:
        resolver = make_resolver(server)
        answer = resolver.resolve(HOST_NAME, "A")
        assert answer[0].address == "10.0.0.1"
        key = (HOST_NAME, dns.rdatatype.A, dns.rdataclass.IN)
        assert key in resolver.cache.data
        # The entry expires and the nameserver starts failing.
        now.sleep(6)
        server.fail = True
        with pytest.raises(dns.resolver.NoNameservers):
            resolver.resolve(HOST_NAME, "A")
        # The expired entry is gone and the failed query did not
        # leave anything behind.
        assert key not in resolver.cache.data
        # When the nameserver recovers, resolution works again.
        server.fail = False
        answer = resolver.resolve(HOST_NAME, "A")
        assert answer[0].address == "10.0.0.1"
        assert server.query_count() == 3


def test_flush():
    server = InMemoryNameserver()
    server.add_record("host.example.", "A", "10.0.0.1")
    with FakeTime():
        resolver = make_resolver(server)
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "A")
        resolver.resolve(HOST_NAME, "A")
        assert server.query_count() == 2
        # Flushing a single key only evicts that entry.
        resolver.cache.flush((HOST_NAME, dns.rdatatype.A, dns.rdataclass.IN))
        resolver.resolve(HOST_NAME, "A")
        assert server.query_count() == 3
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "A")
        assert server.query_count() == 3
        # Flushing everything evicts the NXDOMAIN entry too.
        resolver.cache.flush()
        with pytest.raises(dns.resolver.NXDOMAIN):
            resolver.resolve(NX_NAME, "A")
        assert server.query_count() == 4


def test_separate_caches_do_not_pollute_each_other():
    server1 = InMemoryNameserver()
    server1.add_record("host.example.", "A", "10.0.0.1")
    server2 = InMemoryNameserver()
    server2.add_record("host.example.", "A", "10.0.0.2")
    resolver1 = make_resolver(server1)
    resolver2 = make_resolver(server2)
    assert resolver1.resolve(HOST_NAME, "A")[0].address == "10.0.0.1"
    assert resolver2.resolve(HOST_NAME, "A")[0].address == "10.0.0.2"
    # Each resolver keeps serving its own cached data.
    assert resolver1.resolve(HOST_NAME, "A")[0].address == "10.0.0.1"
    assert resolver2.resolve(HOST_NAME, "A")[0].address == "10.0.0.2"
    assert server1.query_count() == 1
    assert server2.query_count() == 1


def test_search_list_nxdomain_does_not_pollute_other_names():
    server = InMemoryNameserver()
    server.add_record("host.other.", "A", "10.0.0.9")
    with FakeTime():
        resolver = make_resolver(server)
        resolver.search = [
            dns.name.from_text("example."),
            dns.name.from_text("other."),
        ]
        # host.example. is NXDOMAIN, host.other. exists.
        answer = resolver.resolve("host", "A", search=True)
        assert answer[0].address == "10.0.0.9"
        assert server.query_count() == 2
        # Again; the NXDOMAIN for host.example. is cached, but does
        # not make host.other. look nonexistent.
        answer = resolver.resolve("host", "A", search=True)
        assert answer[0].address == "10.0.0.9"
        assert server.query_count() == 2
        # A name that exists nowhere raises NXDOMAIN mentioning all
        # of the names that were tried, including from cached
        # responses.
        with pytest.raises(dns.resolver.NXDOMAIN) as excinfo:
            resolver.resolve("nothing", "A", search=True)
        # nothing.example., nothing.other., and the absolute nothing.
        # are all tried.
        assert server.query_count() == 5
        with pytest.raises(dns.resolver.NXDOMAIN) as excinfo:
            resolver.resolve("nothing", "A", search=True)
        assert server.query_count() == 5
        qnames = excinfo.value.qnames()
        assert dns.name.from_text("nothing.example.") in qnames
        assert dns.name.from_text("nothing.other.") in qnames
        assert dns.name.from_text("nothing.") in qnames
