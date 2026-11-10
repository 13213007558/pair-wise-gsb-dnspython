.. _inbound-xfr-class:

The dns.xfr.Inbound Class and make_query() function
---------------------------------------------------

The ``Inbound`` class provides support for inbound DNS zone transfers,
both AXFR and IXFR.  It is invoked by I/O code, i.e.
:py:func:`dns.query.inbound_xfr` or
:py:func:`dns.asyncquery.inbound_xfr`.  When a message related to the
transfer arrives, the I/O code calls the ``process_message()`` method
which adds the content to the pending transaction.

The ``make_query()`` function is used to making the query message for
the query methods to use in more complex situations, e.g. with TSIG or
EDNS.

The ``AuthenticatedInbound`` class is the secure entry point for code
that receives raw transfer messages over its own transport.  It parses
each message from its wire bytes with the configured TSIG keyring and
maintains the continuous RFC 8945 digest context, so authentication
cannot be forged by setting ``Message.had_tsig`` on an object.  The
writer transaction is only committed once the transfer is both
semantically complete and fully authenticated; every other outcome rolls
the transaction back and leaves the previously visible zone unchanged.

.. autoexception:: dns.xfr.UseTCP

.. autoexception:: dns.xfr.TSIGPolicyError

.. autoexception:: dns.xfr.TransferIncomplete

.. autoclass:: dns.xfr.Inbound
   :members:

.. autoclass:: dns.xfr.AuthenticatedInbound
   :members:

.. autoclass:: dns.xfr.XfrResult
   :members:

.. autofunction:: dns.xfr.make_query
