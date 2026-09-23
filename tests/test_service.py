# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio
import socket
import unittest

import dns.asyncresolver
import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.service
from dns.rdtypes.svcbbase import ParamKey


def make_answer(qname, rdtype, rdatas):
    q = dns.message.make_query(qname, rdtype)
    r = dns.message.make_response(q)
    if rdatas:
        rrset = r.get_rrset(r.answer, qname, dns.rdataclass.IN, rdtype, create=True)
        for text in rdatas:
            rrset.add(dns.rdata.from_text(dns.rdataclass.IN, rdtype, text), 300)
    return dns.resolver.Answer(qname, rdtype, dns.rdataclass.IN, r)


class MemoryResolver:
    """A resolver serving answers from an in-memory dict and recording
    the sequence of queries made."""

    def __init__(self):
        self.data = {}
        self.queries = []

    def add(self, name, rdtype, *rdatas):
        key = (dns.name.from_text(name), dns.rdatatype.RdataType.make(rdtype))
        self.data[key] = list(rdatas)

    def add_error(self, name, rdtype, exception):
        key = (dns.name.from_text(name), dns.rdatatype.RdataType.make(rdtype))
        self.data[key] = exception

    def _resolve(
        self, qname, rdtype=dns.rdatatype.A, raise_on_no_answer=True, **kwargs
    ):
        if not isinstance(qname, dns.name.Name):
            qname = dns.name.from_text(qname)
        rdtype = dns.rdatatype.RdataType.make(rdtype)
        self.queries.append((qname, rdtype))
        value = self.data.get((qname, rdtype))
        if value is None:
            raise dns.resolver.NXDOMAIN(qnames=[qname])
        if isinstance(value, Exception):
            raise value
        if len(value) == 0 and raise_on_no_answer:
            raise dns.resolver.NoAnswer
        return make_answer(qname, rdtype, value)

    def query_log(self):
        return [(q.to_text(), dns.rdatatype.to_text(t)) for q, t in self.queries]


class SyncMemoryResolver(MemoryResolver, dns.resolver.Resolver):
    def __init__(self):
        MemoryResolver.__init__(self)
        dns.resolver.Resolver.__init__(self, configure=False)

    def resolve(self, qname, rdtype=dns.rdatatype.A, **kwargs):
        return self._resolve(qname, rdtype, **kwargs)


class AsyncMemoryResolver(MemoryResolver, dns.asyncresolver.Resolver):
    def __init__(self):
        MemoryResolver.__init__(self)
        dns.asyncresolver.Resolver.__init__(self, configure=False)

    async def resolve(self, qname, rdtype=dns.rdatatype.A, **kwargs):
        return self._resolve(qname, rdtype, **kwargs)


class ServiceTestCase(unittest.TestCase):
    def make_resolver(self, resolver_class=SyncMemoryResolver):
        r = resolver_class()
        # AliasMode: www.example.com is an alias for svc.example.net, which
        # has two ServiceMode records with different priorities.
        r.add("www.example.com", "HTTPS", "0 svc.example.net.")
        r.add(
            "svc.example.net",
            "HTTPS",
            '20 b.example.net. alpn="h2,h3" port=8443',
            '10 a.example.net. alpn="h2"',
        )
        r.add("a.example.net", "A", "192.0.2.1")
        r.add("a.example.net", "AAAA", "2001:db8::1")
        r.add("b.example.net", "A", "192.0.2.2")
        r.add("b.example.net", "AAAA")  # NOERROR, no data
        return r

    def check_alias_and_priorities(self, r, endpoints):
        self.assertEqual([e.priority for e in endpoints], [10, 20])
        ep0, ep1 = endpoints
        self.assertEqual(ep0.target, dns.name.from_text("a.example.net"))
        self.assertEqual(ep0.owner, dns.name.from_text("svc.example.net"))
        self.assertEqual(ep0.alpn, (b"h2",))
        self.assertIsNone(ep0.port)
        self.assertEqual(ep1.target, dns.name.from_text("b.example.net"))
        self.assertEqual(ep1.alpn, (b"h2",))
        self.assertEqual(ep1.port, 8443)
        # Addresses from the A/AAAA lookups, labeled with their source.
        self.assertEqual(
            [(a.address, a.source) for a in ep0.addresses],
            [
                ("2001:db8::1", dns.service.AddressSource.LOOKUP),
                ("192.0.2.1", dns.service.AddressSource.LOOKUP),
            ],
        )
        self.assertEqual(
            [(a.address, a.source) for a in ep1.addresses],
            [("192.0.2.2", dns.service.AddressSource.LOOKUP)],
        )
        self.assertEqual(
            r.query_log(),
            [
                ("www.example.com.", "HTTPS"),
                ("svc.example.net.", "HTTPS"),
                ("a.example.net.", "AAAA"),
                ("a.example.net.", "A"),
                ("b.example.net.", "AAAA"),
                ("b.example.net.", "A"),
            ],
        )

    def test_alias_and_priorities(self):
        r = self.make_resolver()
        endpoints = r.resolve_service("www.example.com", alpn=["h2"])
        self.check_alias_and_priorities(r, endpoints)

    def test_alias_and_priorities_async(self):
        async def run():
            r = self.make_resolver(AsyncMemoryResolver)
            endpoints = await r.resolve_service("www.example.com", alpn=["h2"])
            self.check_alias_and_priorities(r, endpoints)

        asyncio.run(run())

    def test_no_alpn_intersection(self):
        r = self.make_resolver()
        endpoints = r.resolve_service("www.example.com", alpn=["http/1.1"])
        self.assertEqual(endpoints, [])
        # No address queries are made when no records are usable.
        self.assertEqual(
            r.query_log(),
            [
                ("www.example.com.", "HTTPS"),
                ("svc.example.net.", "HTTPS"),
            ],
        )

    def test_family_filtering(self):
        r = self.make_resolver()
        endpoints = r.resolve_service(
            "www.example.com", alpn=["h2"], family=socket.AF_INET
        )
        self.assertEqual([a.address for a in endpoints[0].addresses], ["192.0.2.1"])
        self.assertEqual(
            r.query_log(),
            [
                ("www.example.com.", "HTTPS"),
                ("svc.example.net.", "HTTPS"),
                ("a.example.net.", "A"),
                ("b.example.net.", "A"),
            ],
        )

    def make_hints_resolver(self, resolver_class=SyncMemoryResolver):
        r = resolver_class()
        # The first record uses TargetName "." (the owner name) and only
        # has address hints; address queries for the owner fail.  The
        # second record has a resolvable target.  The failure of the
        # first target's address queries must not drop the second record.
        r.add(
            "hints.example.com",
            "HTTPS",
            '1 . alpn="h2" ipv4hint=192.0.2.10,192.0.2.11 ipv6hint=2001:db8::10',
            '2 good.example.net. alpn="h2"',
        )
        r.add("good.example.net", "A", "192.0.2.20")
        r.add("good.example.net", "AAAA", "2001:db8::20")
        return r

    def check_hints_only(self, r, endpoints):
        self.assertEqual(len(endpoints), 2)
        ep0, ep1 = endpoints
        # TargetName "." means the owner name.
        self.assertEqual(ep0.target, dns.name.from_text("hints.example.com"))
        self.assertEqual(
            [(a.address, a.source) for a in ep0.addresses],
            [
                ("192.0.2.10", dns.service.AddressSource.HINT),
                ("192.0.2.11", dns.service.AddressSource.HINT),
                ("2001:db8::10", dns.service.AddressSource.HINT),
            ],
        )
        # The other record's addresses resolved fine.
        self.assertEqual(
            [(a.address, a.source) for a in ep1.addresses],
            [
                ("2001:db8::20", dns.service.AddressSource.LOOKUP),
                ("192.0.2.20", dns.service.AddressSource.LOOKUP),
            ],
        )
        self.assertEqual(
            r.query_log(),
            [
                ("hints.example.com.", "HTTPS"),
                ("hints.example.com.", "AAAA"),
                ("hints.example.com.", "A"),
                ("good.example.net.", "AAAA"),
                ("good.example.net.", "A"),
            ],
        )

    def test_hints_only(self):
        r = self.make_hints_resolver()
        endpoints = r.resolve_service("hints.example.com", alpn=["h2"])
        self.check_hints_only(r, endpoints)

    def test_hints_only_async(self):
        async def run():
            r = self.make_hints_resolver(AsyncMemoryResolver)
            endpoints = await r.resolve_service("hints.example.com", alpn=["h2"])
            self.check_hints_only(r, endpoints)

        asyncio.run(run())

    def test_no_address_resolution(self):
        r = self.make_hints_resolver()
        endpoints = r.resolve_service(
            "hints.example.com", alpn=["h2"], resolve_addresses=False
        )
        self.assertEqual(len(endpoints), 2)
        self.assertEqual(len(endpoints[0].addresses), 3)
        self.assertEqual(endpoints[1].addresses, ())
        self.assertEqual(r.query_log(), [("hints.example.com.", "HTTPS")])

    def test_mandatory_unknown_param(self):
        r = SyncMemoryResolver()
        r.add(
            "mandatory.example.com",
            "HTTPS",
            '1 a.example.net. alpn="h2" mandatory=key65400 key65400="abc"',
            '2 b.example.net. alpn="h2" key65401="xyz"',
        )
        r.add("a.example.net", "A", "192.0.2.1")
        r.add("b.example.net", "A", "192.0.2.2")
        # The record with the unknown mandatory key is not usable; the
        # unknown optional key on the other record is preserved.
        endpoints = r.resolve_service("mandatory.example.com", alpn=["h2"])
        self.assertEqual([e.priority for e in endpoints], [2])
        self.assertIn(ParamKey.make(65401), endpoints[0].params)
        self.assertEqual(
            r.query_log(),
            [
                ("mandatory.example.com.", "HTTPS"),
                ("b.example.net.", "AAAA"),
                ("b.example.net.", "A"),
            ],
        )
        # Declaring support for the key makes the record usable.
        r = SyncMemoryResolver()
        r.add(
            "mandatory.example.com",
            "HTTPS",
            '1 a.example.net. alpn="h2" mandatory=key65400 key65400="abc"',
            '2 b.example.net. alpn="h2" key65401="xyz"',
        )
        r.add("a.example.net", "A", "192.0.2.1")
        r.add("b.example.net", "A", "192.0.2.2")
        endpoints = r.resolve_service(
            "mandatory.example.com", alpn=["h2"], supported_params=["key65400"]
        )
        self.assertEqual([e.priority for e in endpoints], [1, 2])

    def test_default_alpn(self):
        r = SyncMemoryResolver()
        r.add(
            "default.example.com",
            "HTTPS",
            '1 a.example.net. no-default-alpn alpn="h3"',
            "2 b.example.net.",
        )
        r.add("a.example.net", "A", "192.0.2.1")
        r.add("b.example.net", "A", "192.0.2.2")
        # The caller only supports h2; neither the h3-only record nor the
        # default ALPN (http/1.1 for HTTPS records) is usable.
        endpoints = r.resolve_service("default.example.com", alpn=["h2"])
        self.assertEqual(endpoints, [])
        # The caller supports the default ALPN.
        endpoints = r.resolve_service("default.example.com", alpn=["http/1.1"])
        self.assertEqual([e.priority for e in endpoints], [2])
        self.assertEqual(endpoints[0].alpn, (b"http/1.1",))
        # No ALPN filtering at all.
        endpoints = r.resolve_service("default.example.com")
        self.assertEqual([e.priority for e in endpoints], [1, 2])
        self.assertEqual(endpoints[0].alpn, (b"h3",))
        self.assertEqual(endpoints[1].alpn, (b"http/1.1",))

    def test_alias_loop(self):
        r = SyncMemoryResolver()
        r.add("loop1.example.com", "HTTPS", "0 loop2.example.net.")
        r.add("loop2.example.net", "HTTPS", "0 loop1.example.com.")
        with self.assertRaises(dns.service.AliasLoop):
            r.resolve_service("loop1.example.com")
        # Self-alias
        r = SyncMemoryResolver()
        r.add("self.example.com", "HTTPS", "0 self.example.com.")
        with self.assertRaises(dns.service.AliasLoop):
            r.resolve_service("self.example.com")

    def test_too_many_aliases(self):
        r = SyncMemoryResolver()
        r.add("chain0.example.com", "HTTPS", "0 chain1.example.com.")
        r.add("chain1.example.com", "HTTPS", "0 chain2.example.com.")
        r.add("chain2.example.com", "HTTPS", "0 chain3.example.com.")
        r.add("chain3.example.com", "HTTPS", '1 . alpn="h2"')
        with self.assertRaises(dns.service.TooManyAliases):
            r.resolve_service("chain0.example.com", max_aliases=2)
        # The default limit is enough for this chain.
        endpoints = r.resolve_service("chain0.example.com")
        self.assertEqual(len(endpoints), 1)

    def test_alias_to_root(self):
        # An AliasMode TargetName of "." means the service does not exist.
        r = SyncMemoryResolver()
        r.add("gone.example.com", "HTTPS", "0 .")
        endpoints = r.resolve_service("gone.example.com")
        self.assertEqual(endpoints, [])
        self.assertEqual(r.query_log(), [("gone.example.com.", "HTTPS")])

    def test_svcb_rdtype(self):
        r = SyncMemoryResolver()
        r.add(
            "_dns.example.com",
            "SVCB",
            '1 dns.example.net. alpn="dot" port=853',
        )
        r.add("dns.example.net", "A", "192.0.2.53")
        endpoints = r.resolve_service("_dns.example.com", rdtype="SVCB", alpn=["dot"])
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].port, 853)
        self.assertEqual(endpoints[0].alpn, (b"dot",))
        self.assertEqual(
            r.query_log(),
            [
                ("_dns.example.com.", "SVCB"),
                ("dns.example.net.", "AAAA"),
                ("dns.example.net.", "A"),
            ],
        )

    def test_bad_rdtype(self):
        r = SyncMemoryResolver()
        with self.assertRaises(ValueError):
            r.resolve_service("www.example.com", rdtype="A")

    def test_resolve_kwargs_passed_through(self):
        # resolve() keyword arguments like raise_on_no_answer and
        # lifetime are accepted and do not conflict with the queries
        # resolve_service() makes.
        r = self.make_resolver()
        endpoints = r.resolve_service(
            "www.example.com", alpn=["h2"], raise_on_no_answer=False, lifetime=10.0
        )
        self.assertEqual([e.priority for e in endpoints], [10, 20])

    def test_nxdomain(self):
        r = SyncMemoryResolver()
        with self.assertRaises(dns.resolver.NXDOMAIN):
            r.resolve_service("nonexistent.example.com")

    def test_bad_family(self):
        r = self.make_resolver()
        with self.assertRaises(NotImplementedError):
            r.resolve_service("www.example.com", family=999)

    def test_endpoint_repr(self):
        r = self.make_resolver()
        endpoints = r.resolve_service("www.example.com", alpn=["h2"])
        self.assertIn("ServiceEndpoint", repr(endpoints[0]))
        self.assertIn("ServiceAddress", repr(endpoints[0].addresses[0]))

    def test_svcb_no_alpn_no_default(self):
        # For SVCB records there is no default ALPN; a record without an
        # alpn parameter is compatible with anything.
        r = SyncMemoryResolver()
        r.add("_dns.example.com", "SVCB", "1 dns.example.net. port=853")
        r.add("dns.example.net", "A", "192.0.2.53")
        endpoints = r.resolve_service("_dns.example.com", rdtype="SVCB", alpn=["dot"])
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].alpn, ())

    def test_async_errors(self):
        async def run():
            r = AsyncMemoryResolver()
            r.add("loop1.example.com", "HTTPS", "0 loop2.example.net.")
            r.add("loop2.example.net", "HTTPS", "0 loop1.example.com.")
            with self.assertRaises(dns.service.AliasLoop):
                await r.resolve_service("loop1.example.com")
            r = AsyncMemoryResolver()
            r.add("chain0.example.com", "HTTPS", "0 chain1.example.com.")
            r.add("chain1.example.com", "HTTPS", "0 chain2.example.com.")
            r.add("chain2.example.com", "HTTPS", '1 . alpn="h2"')
            with self.assertRaises(dns.service.TooManyAliases):
                await r.resolve_service("chain0.example.com", max_aliases=1)
            r = AsyncMemoryResolver()
            r.add("gone.example.com", "HTTPS", "0 .")
            endpoints = await r.resolve_service("gone.example.com")
            self.assertEqual(endpoints, [])

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
