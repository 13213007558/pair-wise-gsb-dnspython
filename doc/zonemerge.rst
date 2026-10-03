.. _zonemerge:

Three-way Zone Merges
=====================

.. module:: dns.zonemerge

When two automation branches have independently modified the same zone,
:py:func:`dns.zonemerge.merge_zones` performs a three-way merge of the
zone against their common ancestor, returning either a new
:py:class:`dns.zone.Zone` or a list of structured conflicts.  The input
zones are never modified.

.. autofunction:: dns.zonemerge.merge_zones

.. autofunction:: dns.zonemerge.increment_serial_policy

.. autoclass:: dns.zonemerge.MergeResult
   :members:

.. autoclass:: dns.zonemerge.Conflict
   :members:

.. autoclass:: dns.zonemerge.RrsetKey
   :members:

.. autoclass:: dns.zonemerge.ConflictReason
   :members:

.. autoexception:: dns.zonemerge.BadSerial

.. autoexception:: dns.zonemerge.IncompatibleZones
