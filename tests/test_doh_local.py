# Copyright (C) Dnspython Contributors, see LICENSE for text of ISC license

# Tests for the DoH request/response matching and retry policy, using a
# local HTTP server.  These tests exercise the transport-neutral core of
# dns.query.https() and dns.asyncquery.https() without requiring httpx2.

import asyncio
import base64
import http.client
import http.server
import threading
import urllib.parse

import pytest

import dns.asyncquery
import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.rrset

from tests.nanonameserver import ConnectionType, Server

WHERE = "https://127.0.0.1/dns-query"


class RecordedRequest:
    def __init__(self, method, path, headers, body):
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body


def respond(
    handler,
    status=200,
    body=b"",
    content_type="application/dns-message",
    extra_headers=None,
):
    handler.send_response(status)
    if content_type is not None:
        handler.send_header("Content-Type", content_type)
    if extra_headers:
        for name, value in extra_headers.items():
            handler.send_header(name, value)
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    if body:
        handler.wfile.write(body)


def message_step(message, content_type="application/dns-message"):
    def step(handler):
        respond(handler, 200, message.to_wire(), content_type)

    return step


def status_step(status, extra_headers=None):
    def step(handler):
        respond(handler, status, b"error", "text/plain", extra_headers)

    return step


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        self.server.record_and_respond(self)

    def do_POST(self):
        self.server.record_and_respond(self)


class DoHServer(http.server.ThreadingHTTPServer):
    """A local HTTP server playing a scripted sequence of DoH responses.

    Every request's method, URL, headers, and body are recorded in
    self.requests.
    """

    daemon_threads = True

    def __init__(self, script):
        super().__init__(("127.0.0.1", 0), Handler)
        self.script = list(script)
        self.requests = []
        self.thread = threading.Thread(target=self.serve_forever)
        self.thread.start()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.shutdown()
        self.thread.join()
        self.server_close()

    @property
    def port(self):
        return self.server_address[1]

    def record_and_respond(self, handler):
        length = int(handler.headers.get("content-length") or 0)
        body = handler.rfile.read(length) if length else None
        self.requests.append(
            RecordedRequest(handler.command, handler.path, handler.headers, body)
        )
        step = self.script.pop(0)
        step(handler)


def make_sender(port, post):
    """Make a send() callable for _doh_exchange() that speaks to the local
    server with the stdlib HTTP client."""

    def send(request):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            if post:
                path = "/dns-query"
                body = request.content
            else:
                path = "/dns-query?" + urllib.parse.urlencode(request.params)
                body = None
            conn.request(
                "POST" if post else "GET", path, body=body, headers=request.headers
            )
            response = conn.getresponse()
            content = response.read()
            return dns.query._DoHResponse(
                response.status, dict(response.getheaders()), content, 0.1
            )
        finally:
            conn.close()

    return send


def exchange(server, q, post=True, **kwargs):
    send = make_sender(server.port, post)
    params = {
        "where": WHERE,
        "validate": True,
        "http_retries": 0,
        "servfail_retries": 0,
        "one_rr_per_rrset": False,
        "ignore_trailing": False,
    }
    params.update(kwargs)
    return dns.query._doh_exchange(q, post, send, **params)


def make_query():
    return dns.message.make_query("example.com.", dns.rdatatype.A)


def good_response(q):
    r = dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text("example.com.", 300, "in", "A", "192.0.2.1"))
    return r


def wrong_question_response(q):
    other = dns.message.make_query("other.example.", dns.rdatatype.A, id=q.id)
    return dns.message.make_response(other)


def wrong_id_response(q):
    r = dns.message.make_response(q)
    r.id = (q.id + 1) % 65536
    return r


def truncated_response(q):
    r = dns.message.make_response(q)
    r.flags |= dns.flags.TC
    return r


def servfail_response(q):
    r = dns.message.make_response(q)
    r.set_rcode(dns.rcode.SERVFAIL)
    return r


def test_post_request_encoding():
    q = make_query()
    with DoHServer([message_step(good_response(q))]) as server:
        r, _ = exchange(server, q, post=True)
        assert q.is_response(r)
        assert len(server.requests) == 1
        request = server.requests[0]
        assert request.method == "POST"
        assert request.path == "/dns-query"
        # The body is exactly the wire format of the query, so it can be
        # reproduced from a packet capture.
        assert request.body == q.to_wire()
        assert request.headers["content-type"] == "application/dns-message"
        assert request.headers["content-length"] == str(len(q.to_wire()))
        assert request.headers["accept"] == "application/dns-message"


def test_get_request_encoding():
    q = make_query()
    with DoHServer([message_step(good_response(q))]) as server:
        r, _ = exchange(server, q, post=False)
        assert q.is_response(r)
        assert len(server.requests) == 1
        request = server.requests[0]
        assert request.method == "GET"
        assert request.body is None
        parsed = urllib.parse.urlparse(request.path)
        assert parsed.path == "/dns-query"
        params = urllib.parse.parse_qs(parsed.query)
        encoded = params["dns"][0]
        # base64url without padding, per RFC 8484 section 4.1.1
        assert "=" not in encoded
        encoded += "=" * (-len(encoded) % 4)
        assert base64.urlsafe_b64decode(encoded) == q.to_wire()


def test_wrong_question_rejected():
    q = make_query()
    with DoHServer([message_step(wrong_question_response(q))]) as server:
        with pytest.raises(dns.query.BadResponse):
            exchange(server, q)
        assert len(server.requests) == 1


def test_wrong_id_rejected():
    q = make_query()
    with DoHServer([message_step(wrong_id_response(q))]) as server:
        with pytest.raises(dns.query.BadResponse):
            exchange(server, q)
        assert len(server.requests) == 1


def test_wrong_media_type_rejected():
    q = make_query()
    steps = [message_step(good_response(q), content_type="text/html")]
    with DoHServer(steps) as server:
        with pytest.raises(dns.query.BadResponse):
            exchange(server, q)
        assert len(server.requests) == 1


def test_media_type_parameters_accepted():
    q = make_query()
    steps = [message_step(good_response(q), content_type="application/dns-message;")]
    with DoHServer(steps) as server:
        r, _ = exchange(server, q)
        assert q.is_response(r)


def test_validation_can_be_disabled():
    q = make_query()
    steps = [message_step(good_response(q), content_type="text/html")]
    with DoHServer(steps) as server:
        r, _ = exchange(server, q, validate=False)
        assert q.is_response(r)


def test_truncated_response_returned():
    q = make_query()
    with DoHServer([message_step(truncated_response(q))]) as server:
        r, _ = exchange(server, q)
        assert r.flags & dns.flags.TC


def test_http_429_retries():
    q = make_query()
    steps = [status_step(429), status_step(429), message_step(good_response(q))]
    with DoHServer(steps) as server:
        r, _ = exchange(server, q, http_retries=2)
        assert q.is_response(r)
        assert len(server.requests) == 3
        # The same immutable body is resent on every retry; nothing is
        # re-consumed or mutated.
        assert all(req.body == q.to_wire() for req in server.requests)
        assert all(req.method == "POST" for req in server.requests)


def test_http_429_retry_budget_exhausted():
    q = make_query()
    steps = [status_step(429), status_step(429), message_step(good_response(q))]
    with DoHServer(steps) as server:
        with pytest.raises(ValueError):
            exchange(server, q, http_retries=1)
        assert len(server.requests) == 2


def test_http_503_retry():
    q = make_query()
    steps = [status_step(503), message_step(good_response(q))]
    with DoHServer(steps) as server:
        r, _ = exchange(server, q, http_retries=1)
        assert q.is_response(r)
        assert len(server.requests) == 2


def test_redirect_not_followed():
    q = make_query()
    steps = [status_step(302, {"Location": "https://evil.example/dns-query"})]
    with DoHServer(steps) as server:
        with pytest.raises(ValueError):
            exchange(server, q)
        # The redirect was not followed, so no headers leaked to another
        # origin.
        assert len(server.requests) == 1


def test_servfail_retries():
    q = make_query()
    steps = [message_step(servfail_response(q)), message_step(good_response(q))]
    with DoHServer(steps) as server:
        r, _ = exchange(server, q, servfail_retries=1)
        assert q.is_response(r)
        assert r.rcode() == dns.rcode.NOERROR
        assert len(server.requests) == 2


def test_servfail_returned_without_budget():
    q = make_query()
    with DoHServer([message_step(servfail_response(q))]) as server:
        r, _ = exchange(server, q)
        assert r.rcode() == dns.rcode.SERVFAIL
        assert len(server.requests) == 1


def test_http_and_servfail_budgets_are_separate():
    q = make_query()
    # A 429 does not consume the SERVFAIL budget.
    with DoHServer([status_step(429)]) as server:
        with pytest.raises(ValueError):
            exchange(server, q, servfail_retries=2)
        assert len(server.requests) == 1
    # A SERVFAIL does not consume the HTTP budget.
    with DoHServer([message_step(servfail_response(q))]) as server:
        r, _ = exchange(server, q, http_retries=2)
        assert r.rcode() == dns.rcode.SERVFAIL
        assert len(server.requests) == 1


def test_scripted_sequence():
    # The server returns, in sequence: a wrong question, a truncated
    # response, a 429, and finally a valid response.
    q = make_query()
    steps = [
        message_step(wrong_question_response(q)),
        message_step(truncated_response(q)),
        status_step(429),
        message_step(good_response(q)),
    ]
    with DoHServer(steps) as server:
        with pytest.raises(dns.query.BadResponse):
            exchange(server, q)
        r, _ = exchange(server, q)
        assert r.flags & dns.flags.TC
        r, _ = exchange(server, q, http_retries=1)
        assert q.is_response(r)
        assert not (r.flags & dns.flags.TC)
        assert len(server.requests) == 4
        for request in server.requests:
            assert request.method == "POST"
            assert request.path == "/dns-query"
            assert request.body == q.to_wire()


class TcpFallbackServer(Server):
    def __init__(self, response):
        super().__init__(protocols=(ConnectionType.TCP,))
        self.response = response

    def handle(self, request):
        return self.response


def test_truncation_tcp_fallback():
    q = make_query()
    full = good_response(q)
    with TcpFallbackServer(full) as ns:
        tcp_port = ns.get_address(ConnectionType.TCP)[1]
        r = dns.query._doh_truncation_fallback(
            q, "tcp", "127.0.0.1", 10.0, None, 0, False, False, True, tcp_port
        )
        assert q.is_response(r)
        assert not (r.flags & dns.flags.TC)
        assert r.answer


def test_truncation_target():
    assert dns.query._doh_truncation_target("192.0.2.1") == "192.0.2.1"
    assert (
        dns.query._doh_truncation_target("https://dns.example/dns-query")
        == "dns.example"
    )
    assert (
        dns.query._doh_truncation_target("https://dns.example:4443/dns-query")
        == "dns.example"
    )


def async_exchange(server, q, post=True, **kwargs):
    sync_send = make_sender(server.port, post)

    async def send(request):
        return sync_send(request)

    params = {
        "where": WHERE,
        "validate": True,
        "http_retries": 0,
        "servfail_retries": 0,
        "one_rr_per_rrset": False,
        "ignore_trailing": False,
    }
    params.update(kwargs)
    return dns.asyncquery._async_doh_exchange(q, post, send, **params)


def test_async_exchange_matches_sync():
    q = make_query()
    steps = [status_step(429), message_step(good_response(q))]
    with DoHServer(steps) as server:
        r, _ = asyncio.run(async_exchange(server, q, http_retries=1))
        assert q.is_response(r)
        assert len(server.requests) == 2


def test_async_exchange_error_types_match_sync():
    q = make_query()
    steps = [message_step(wrong_question_response(q))]
    with DoHServer(steps) as server:
        with pytest.raises(dns.query.BadResponse):
            asyncio.run(async_exchange(server, q))
    steps = [status_step(503)]
    with DoHServer(steps) as server:
        with pytest.raises(ValueError):
            asyncio.run(async_exchange(server, q))


def test_async_truncation_tcp_fallback():
    q = make_query()
    full = good_response(q)
    with TcpFallbackServer(full) as ns:
        tcp_port = ns.get_address(ConnectionType.TCP)[1]

        async def main():
            return await dns.asyncquery._async_doh_truncation_fallback(
                q, "tcp", "127.0.0.1", 10.0, None, 0, False, False, True, tcp_port, None
            )

        r = asyncio.run(main())
        assert q.is_response(r)
        assert not (r.flags & dns.flags.TC)
        assert r.answer
