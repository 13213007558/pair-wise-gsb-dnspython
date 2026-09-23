.. _service:

Service Discovery
=================

.. module:: dns.service

Dnspython implements DNS service discovery using SVCB and HTTPS records
as specified in RFC 9460.  The entry points are
:py:meth:`dns.resolver.Resolver.resolve_service` and
:py:meth:`dns.asyncresolver.Resolver.resolve_service`, which return a list
of :py:class:`ServiceEndpoint` candidates the caller may connect to; no
TCP, TLS, or QUIC connections are made by the discovery process itself.

.. autoclass:: dns.service.ServiceEndpoint
   :members:

.. autoclass:: dns.service.ServiceAddress
   :members:

.. autoclass:: dns.service.AddressSource
   :members:

.. autodata:: dns.service.DEFAULT_MAX_ALIASES
