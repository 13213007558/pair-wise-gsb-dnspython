.. module:: dns.authoritative
.. _authoritative:

Authoritative Answer Support
============================

The :py:mod:`dns.authoritative` module generates authoritative
responses to DNS queries from a :py:class:`dns.zone.Zone` snapshot.
It is intended for embedding in test services and other situations
where a full DNS server is not needed.  It supports closest-encloser
wildcard matching, empty non-terminals, delegation referrals with
in-bailiwick glue, and in-zone CNAME chasing for class IN A, AAAA, and
CNAME queries.  DNSSEC, DNAME, and recursion are not supported.

.. autofunction:: dns.authoritative.answer

.. autoexception:: dns.authoritative.CnameLoop

.. autoexception:: dns.authoritative.CnameChainTooLong

