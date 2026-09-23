.. module:: dns.zonemd
.. _zonemd:

ZONEMD Zone Digests
===================

The :py:mod:`dns.zonemd` module implements RFC 8976 zone message digests.
It is a complete entry point for authoritative servers and zone publishers
that need to generate a ZONEMD RRset before publishing a zone, or that
need to verify the digest of a zone loaded from elsewhere, e.g. after a
zone transfer.

ZONEMD Functions
----------------

.. autofunction:: dns.zonemd.compute_zonemd
.. autofunction:: dns.zonemd.verify_zonemd
