.. _message-update:

The dns.update.UpdateMessage Class
----------------------------------

The :py:class:`dns.update.UpdateMessage` class is used for DNS Dynamic Update
messages.  It provides section access using the DNS Dynamic Update
section names, and a variety of convenience methods for constructing
dynamic updates.

.. autoclass:: dns.update.UpdateMessage
   :members:

The following constants may be used to specify sections in the
``find_rrset()`` and ``get_rrset()`` methods:

.. autodata:: dns.update.ZONE
.. autodata:: dns.update.PREREQ
.. autodata:: dns.update.UPDATE
.. autodata:: dns.update.ADDITIONAL

Applying an Update to a Zone
----------------------------

The :py:func:`dns.update.apply` function implements the server side of
RFC 2136.  It checks an update message's prerequisites and, if they all
hold, applies its changes to a zone in a single transaction, returning
the resulting rcode.  The message is taken to have already been
authenticated and authorized, and is not modified by the call.

.. autofunction:: dns.update.apply
