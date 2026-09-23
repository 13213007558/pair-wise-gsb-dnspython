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

Applying Updates to Zones
---------------------------

The :py:func:`dns.update.apply_update` function applies a dynamic update
message to a zone, checking the prerequisites of the message and then
applying its update section atomically, per RFC 2136.

.. autofunction:: dns.update.apply_update
