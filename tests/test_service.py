# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

import asyncio

import pytest

import dns.asyncresolver
import dns.exception
import dns.message
import dns.name
import dns.nameserver
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.svcbbase
import dns.resolver
import dns.service


class FakeNameserver(dns.nameserver.Nameserver):
    """An in-memory nameserver answering from a table of
    (qname, rdtype) -> list of rdata text, None for NODATA, or an
    exception to raise.  Records the sequence of queries made."""

    def __init__(self, table):
        super().__init__()
        self.table = table
        self.queries = []

    def __str__(self):
        return "fake"

    def kind(self):
        return "fake"

    def is_always_max_size(self):
        return False

    def answer_nameserver(self):
        return "10.0.0.1"

    def answer_port(self):
        return 53

    def respond(self, request):
        q = request.question[0]
        self.queries.append((q.name, q.rdtype))
        key = (q.name.to_text(), dns.rdatatype.to_text(q.rdtype))
        value = self.table.get(key)
        if isinstance(value, Exception):
            raise value
        response = dns.message.make_response(request)
        if value is not None:
            for text in value:
                rrs = response.get_rrset(
                    response.answer, q.name, dns.rdataclass.IN, q.rdtype, create=True
                )
                rrs.add(dns.rdata.from_text(dns.rdataclass.IN, q.rdtype, text), 300)
        return response

    def query(self, request, **kwargs):
        return self.respond(request)

    async def async_query(self, request, **kwargs):
        return self.respond(request)

    def query_names(self):
        return [
            (name.to_text(), dns.rdatatype.to_text(rdtype))
            for name, rdtype in self.queries
        ]


def make_resolver(table):
    nameserver = FakeNameserver(table)
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    return resolver, nameserver


def make_async_resolver(table):
    nameserver = FakeNameserver(table)
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [nameserver]
    return resolver, nameserver


ALIAS_TABLE = {
    ("example.com.", "HTTPS"): ["0 svc.example.com."],
    ("svc.example.com.", "HTTPS"): [
        "1 . alpn=h2 port=8443 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1",
        "2 alt.example.com. alpn=h2,h3",
    ],
    ("alt.example.com.", "AAAA"): ["2001:db8::2"],
    ("alt.example.com.", "A"): ["192.0.2.2"],
    # svc.example.com. has no address records, only hints.
    ("svc.example.com.", "AAAA"): None,
    ("svc.example.com.", "A"): None,
}


def check_alias_then_priorities(endpoints, nameserver):
    assert len(endpoints) == 2

    # Priority 1: TargetName "." means the owner name, port and hints
    # from the record.
    ep = endpoints[0]
    assert ep.priority == 1
    assert ep.name == dns.name.from_text("svc.example.com")
    assert ep.owner == dns.name.from_text("svc.example.com")
    assert ep.rdtype == dns.rdatatype.HTTPS
    assert ep.port == 8443
    assert ep.alpns == (b"h2",)
    assert [(a.address, a.source) for a in ep.addresses] == [
        ("192.0.2.1", dns.service.AddressSource.HINT),
        ("2001:db8::1", dns.service.AddressSource.HINT),
    ]

    # Priority 2: default port, addresses from A/AAAA queries.
    ep = endpoints[1]
    assert ep.priority == 2
    assert ep.name == dns.name.from_text("alt.example.com")
    assert ep.port == 443
    assert ep.alpns == (b"h2",)
    assert [(a.address, a.source) for a in ep.addresses] == [
        ("2001:db8::2", dns.service.AddressSource.QUERY),
        ("192.0.2.2", dns.service.AddressSource.QUERY),
    ]

    assert nameserver.query_names() == [
        ("example.com.", "HTTPS"),
        ("svc.example.com.", "HTTPS"),
        ("svc.example.com.", "AAAA"),
        ("svc.example.com.", "A"),
        ("alt.example.com.", "AAAA"),
        ("alt.example.com.", "A"),
    ]


def test_alias_then_multiple_priorities():
    resolver, nameserver = make_resolver(ALIAS_TABLE)
    endpoints = resolver.resolve_service(
        "example.com", alpn=[b"h2", b"http/1.1"], port=443
    )
    check_alias_then_priorities(endpoints, nameserver)


def test_alias_then_multiple_priorities_async():
    async def run():
        resolver, nameserver = make_async_resolver(ALIAS_TABLE)
        endpoints = await resolver.resolve_service(
            "example.com", alpn=[b"h2", b"http/1.1"], port=443
        )
        check_alias_then_priorities(endpoints, nameserver)

    asyncio.run(run())


def test_no_alpn_intersection():
    table = {
        ("example.com.", "HTTPS"): [
            "1 . alpn=h3",
            "2 . alpn=h2",
        ],
        ("example.com.", "AAAA"): None,
        ("example.com.", "A"): None,
    }
    resolver, _ = make_resolver(table)
    # Only h3 is offered by the priority 1 record; the caller does not
    # support it, so only the priority 2 record is usable.
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2"])
    assert len(endpoints) == 1
    assert endpoints[0].priority == 2
    # The caller supports nothing the records offer.
    endpoints = resolver.resolve_service("example.com", alpn=[b"http/1.1"])
    assert endpoints == []


def test_default_alpn():
    table = {
        ("example.com.", "HTTPS"): [
            "1 . port=8443",
            "2 . alpn=h2 no-default-alpn",
        ],
        ("example.com.", "AAAA"): None,
        ("example.com.", "A"): None,
    }
    resolver, _ = make_resolver(table)
    # The priority 1 record has no alpn parameter, so it defaults to
    # http/1.1; the priority 2 record has no-default-alpn and only
    # offers h2.
    endpoints = resolver.resolve_service("example.com", alpn=[b"http/1.1"])
    assert [ep.priority for ep in endpoints] == [1]
    assert endpoints[0].alpns == (b"http/1.1",)
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2"])
    assert [ep.priority for ep in endpoints] == [2]
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2", b"http/1.1"])
    assert [ep.priority for ep in endpoints] == [1, 2]


def test_hints_only():
    table = {
        ("example.com.", "HTTPS"): [
            "1 . alpn=h2 ipv4hint=192.0.2.1,192.0.2.2 ipv6hint=2001:db8::1",
        ],
        ("example.com.", "AAAA"): dns.exception.Timeout(),
        ("example.com.", "A"): dns.exception.Timeout(),
    }
    resolver, _ = make_resolver(table)
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2"], port=443)
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert [(a.address, a.source) for a in ep.addresses] == [
        ("192.0.2.1", dns.service.AddressSource.HINT),
        ("192.0.2.2", dns.service.AddressSource.HINT),
        ("2001:db8::1", dns.service.AddressSource.HINT),
    ]
    assert "192.0.2.1" in repr(ep.addresses[0])


def test_address_query_failure_isolated():
    table = {
        ("example.com.", "HTTPS"): [
            "1 good.example.com. alpn=h2",
            "2 bad.example.com. alpn=h2",
        ],
        ("good.example.com.", "AAAA"): None,
        ("good.example.com.", "A"): ["192.0.2.1"],
        ("bad.example.com.", "AAAA"): dns.exception.Timeout(),
        ("bad.example.com.", "A"): dns.exception.Timeout(),
    }
    resolver, _ = make_resolver(table)
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2"], port=443)
    assert len(endpoints) == 2
    assert [a.address for a in endpoints[0].addresses] == ["192.0.2.1"]
    assert endpoints[0].addresses[0].source == dns.service.AddressSource.QUERY
    # The failing target yields an endpoint with no addresses rather
    # than breaking the whole discovery.
    assert endpoints[1].addresses == ()


def test_mandatory_unknown_param():
    table = {
        ("example.com.", "HTTPS"): [
            '1 . alpn=h2 mandatory=key65400 key65400="abc"',
            "2 . alpn=h2",
        ],
        ("example.com.", "AAAA"): None,
        ("example.com.", "A"): None,
    }
    resolver, _ = make_resolver(table)
    # The caller does not support key65400, so the priority 1 record is
    # not usable.
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2"])
    assert [ep.priority for ep in endpoints] == [2]
    # Declaring support makes it usable, and the unknown parameter is
    # preserved.
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2"], params=[65400])
    assert [ep.priority for ep in endpoints] == [1, 2]
    param = endpoints[0].params[dns.rdtypes.svcbbase.ParamKey.make(65400)]
    assert param.value == b"abc"


def test_optional_unknown_param_preserved():
    table = {
        ("example.com.", "HTTPS"): [
            '1 . alpn=h2 key65400="abc"',
        ],
        ("example.com.", "AAAA"): None,
        ("example.com.", "A"): None,
    }
    resolver, _ = make_resolver(table)
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2"])
    assert len(endpoints) == 1
    param = endpoints[0].params[dns.rdtypes.svcbbase.ParamKey.make(65400)]
    assert param.value == b"abc"


def test_alias_loop():
    table = {
        ("a.example.", "HTTPS"): ["0 b.example."],
        ("b.example.", "HTTPS"): ["0 a.example."],
    }
    resolver, _ = make_resolver(table)
    with pytest.raises(dns.service.AliasLoop):
        resolver.resolve_service("a.example", alpn=[b"h2"])


def test_self_alias_loop():
    table = {
        ("a.example.", "HTTPS"): ["0 a.example."],
    }
    resolver, _ = make_resolver(table)
    with pytest.raises(dns.service.AliasLoop):
        resolver.resolve_service("a.example", alpn=[b"h2"])


def test_too_many_aliases():
    table = {
        ("a.example.", "HTTPS"): ["0 b.example."],
        ("b.example.", "HTTPS"): ["0 c.example."],
        ("c.example.", "HTTPS"): ["1 . alpn=h2"],
    }
    resolver, _ = make_resolver(table)
    with pytest.raises(dns.service.TooManyAliases):
        resolver.resolve_service("a.example", alpn=[b"h2"], max_aliases=1)
    # With a sufficient limit the chain resolves.
    endpoints = resolver.resolve_service("a.example", alpn=[b"h2"], max_aliases=2)
    assert len(endpoints) == 1
    assert endpoints[0].owner == dns.name.from_text("c.example")


def test_alias_to_root_means_no_service():
    table = {
        ("example.com.", "HTTPS"): ["0 ."],
    }
    resolver, _ = make_resolver(table)
    assert resolver.resolve_service("example.com", alpn=[b"h2"]) == []


def test_nodata():
    resolver, _ = make_resolver({})
    name = dns.name.from_text("example.com")
    assert resolver.resolve_service(name, alpn=[b"h2"]) == []


def test_svcb_rdtype():
    table = {
        ("_dns.example.", "SVCB"): [
            "1 . alpn=dot port=853",
        ],
        ("_dns.example.", "AAAA"): None,
        ("_dns.example.", "A"): ["192.0.2.53"],
    }
    resolver, _ = make_resolver(table)
    endpoints = resolver.resolve_service("_dns.example", alpn=[b"dot"], rdtype="SVCB")
    assert len(endpoints) == 1
    ep = endpoints[0]
    assert ep.rdtype == dns.rdatatype.SVCB
    assert ep.port == 853
    assert ep.alpns == (b"dot",)
    assert [a.address for a in ep.addresses] == ["192.0.2.53"]


def test_alpn_strings_accepted():
    table = {
        ("example.com.", "HTTPS"): ["1 . alpn=h2"],
        ("example.com.", "AAAA"): None,
        ("example.com.", "A"): None,
    }
    resolver, _ = make_resolver(table)
    endpoints = resolver.resolve_service("example.com", alpn=["h2"])
    assert len(endpoints) == 1


def test_endpoint_immutable():
    table = {
        ("example.com.", "HTTPS"): ["1 . alpn=h2"],
        ("example.com.", "AAAA"): None,
        ("example.com.", "A"): None,
    }
    resolver, _ = make_resolver(table)
    endpoints = resolver.resolve_service("example.com", alpn=[b"h2"])
    with pytest.raises(TypeError):
        endpoints[0].port = 1
    assert "example.com" in repr(endpoints[0])


def test_hints_only_async():
    async def run():
        table = {
            ("example.com.", "HTTPS"): [
                "1 . alpn=h2 ipv4hint=192.0.2.1",
            ],
            ("example.com.", "AAAA"): dns.exception.Timeout(),
            ("example.com.", "A"): dns.exception.Timeout(),
        }
        resolver, _ = make_async_resolver(table)
        endpoints = await resolver.resolve_service(
            "example.com", alpn=[b"h2"], port=443
        )
        assert len(endpoints) == 1
        assert [(a.address, a.source) for a in endpoints[0].addresses] == [
            ("192.0.2.1", dns.service.AddressSource.HINT),
        ]

    asyncio.run(run())
