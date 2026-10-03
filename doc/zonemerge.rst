.. module:: dns.zonemerge
.. _zonemerge:

Three-Way Zone Merging
======================

The :py:mod:`dns.zonemerge` module merges two independently edited copies
of a DNS zone, given their common ancestor zone.  It works like a
three-way source-code merge:

- a merge **unit** is an RRset, identified by its owner name, class,
  type, and covers value;
- a unit's **value** is its TTL together with the set of its normalized
  rdatas;
- a change made on only one side is accepted, and identical changes on
  both sides are also accepted;
- different changes to the same unit, or deleting a unit one side
  modified, are reported as conflicts; rdata sets are never silently
  unioned together.

Owner-name letter case, relative versus absolute spelling of names, and
record ordering are normalized before comparison, so they do not cause
spurious conflicts.  The three input zones are never modified; the
merged zone is always a fresh :py:class:`dns.zone.Zone`.

After the units have been merged, zone-wide constraints are checked on
the combined result: a node may not contain both a CNAME and other
data, and the zone origin must contain a valid SOA and NS RRset.

The SOA serial is set by a caller-supplied *serial policy*, a callable
which receives the base, ours, and theirs serials (each an ``int`` or
``None``) and returns the serial to use.  The returned serial is
validated using RFC 1982 serial number arithmetic: it must not be
earlier than either branch serial.  The default policy is
:py:func:`latest_serial`, which selects the latest branch serial using
serial arithmetic rather than the plain integer maximum.

Example: two branches each add a different host, so the merge takes
both::

   merged = dns.zonemerge.merge(base, ours, theirs)

If both sides change the TTL of the same RRset differently, the merge
cannot resolve it automatically, and the conflicting values (base,
ours, and theirs) are reported::

   try:
       merged = dns.zonemerge.merge(base, ours, theirs)
   except dns.zonemerge.MergeConflicts as e:
       for conflict in e.conflicts:
           print(
               conflict.name,
               conflict.reason.value,
               conflict.base,
               conflict.ours,
               conflict.theirs,
           )

:py:func:`merge` either returns the merged zone or raises
:py:class:`MergeConflicts`; :py:func:`try_merge` instead returns a
:py:class:`MergeResult` containing either the merged zone or a
stable-ordered tuple of :py:class:`MergeConflict` objects.

.. autofunction:: dns.zonemerge.merge

.. autofunction:: dns.zonemerge.try_merge

.. autoclass:: dns.zonemerge.MergeResult
   :members:

.. autoclass:: dns.zonemerge.MergeConflict
   :members:

.. autoclass:: dns.zonemerge.ConflictReason
   :members:
   :undoc-members:

.. autoexception:: dns.zonemerge.MergeConflicts
   :members:

.. autoexception:: dns.zonemerge.MergeError
   :members:

Serial Policies
---------------

A serial policy is a callable with the signature
``(base_serial, ours_serial, theirs_serial) -> int`` where each input
serial is an ``int`` or ``None`` (when that side has no SOA).

.. autofunction:: dns.zonemerge.latest_serial

.. autofunction:: dns.zonemerge.ours_serial

.. autofunction:: dns.zonemerge.theirs_serial

.. autofunction:: dns.zonemerge.increment_serial
