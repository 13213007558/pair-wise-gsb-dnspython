.. _outbound-xfr-class:

The dns.xfr.Outbound Class
--------------------------

The ``Outbound`` class provides support for outbound DNS zone transfers,
both AXFR and IXFR, i.e. it is the server side of a zone transfer.  Given
the client's query, the current contents of the zone, and, for IXFRs, the
consecutive historical versions of the zone reaching back to the client's
version (for example reader transactions on a
:py:class:`dns.versioned.Zone`), iterating over it yields the sequence of
response messages to send to the client.  The messages are ready to be
encoded with :py:meth:`dns.message.Message.to_wire`.

IXFR responses are generated per RFC 1995, and serial numbers are
compared using RFC 1982 serial number arithmetic.

.. autoexception:: dns.xfr.UndefinedSerialOrder

.. autoexception:: dns.xfr.IXFRHistoryUnavailable

.. autoclass:: dns.xfr.Outbound
   :members:
