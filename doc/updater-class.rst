.. _updater-class:

The dns.updater Module
----------------------

The :py:mod:`dns.updater` module applies an
:py:class:`dns.update.UpdateMessage` (RFC 2136 dynamic update) to a
:py:class:`dns.transaction.TransactionManager`, such as an in-memory
:py:class:`dns.zone.Zone` or :py:class:`dns.versioned.Zone`.  It performs
no name service and opens no network sockets, so it is suitable for
offline validation of updates and for policy testing.

The update is processed inside a single writer transaction.  The zone
section, rdata class and the zone scope of every name are checked first;
the prerequisites are then evaluated against the transaction's
pre-update snapshot, and only when all of them hold is the update
section applied in request order.  A failure at any point rolls the
transaction back, leaving the zone unchanged.

TSIG authentication is not performed by this module.  The caller must
authenticate the message before calling it; the key name carried by a
message is never treated as authorization.  A trusted admission
callback may be supplied as *transaction_setup* to install checks on
the transaction; raising from the callback aborts and rolls back the
update.

.. automodule:: dns.updater
   :members:
   :special-members:
