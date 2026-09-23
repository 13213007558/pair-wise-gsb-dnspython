.. module:: dns.zonemd
.. _zonemd:

ZONEMD Zone Digests
===================

The :py:mod:`dns.zonemd` module implements RFC 8976 zone digests.  A
publisher uses :py:func:`dns.zonemd.compute_zonemd` to generate a ZONEMD
record when publishing a zone, optionally attaching it to the zone as a
new RRset.  A receiver uses :py:func:`dns.zonemd.verify_zonemd` to verify
the digests of a zone loaded from a remote source; each ZONEMD record is
verified individually and a per-record diagnostic is returned.

.. autofunction:: dns.zonemd.compute_zonemd
.. autofunction:: dns.zonemd.verify_zonemd
.. autoclass:: dns.zonemd.ZonemdStatus
   :members:
.. autoclass:: dns.zonemd.ZonemdDiagnostic
   :members:
   :undoc-members:
