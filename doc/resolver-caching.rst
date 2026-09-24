.. _resolver-caching:

Resolver Caching Classes
========================

The dnspython resolver does not cache by default, but caching can be
enabled by creating a cache and assigning it to the resolver's *cache*
attribute.  If a cache has been configured, the resolver caches both
positive and negative responses.  The cache respects the DNS TTL of
the data, and will not return expired entries.

Negative responses are cached according to the RFC 2308 negative
caching TTL, i.e. the minimum of the SOA record's TTL and its minimum
field, further reduced by the TTLs of any CNAMEs in the chain.  An
NXDOMAIN response is cached under the query name with the
:py:attr:`dns.rdatatype.NXNAME` meta-type, as the nonexistence of a
name applies to all query types.  A NODATA response (NOERROR with an
empty answer section) is cached under the full (name, type, class)
query key, as it only denies that particular type at the name.  The
NXNAME meta-type is not a valid query type, so the two kinds of
negative entries can never collide with each other or with positive
entries.

Two thread-safe cache implementations are provided, a simple
dictionary-based Cache, and an LRUCache which provides cache size
control suitable for use in web crawlers.  Both are subclasses of
a common base class which provides basic statistics.  The LRUCache can
also provide a hits count per cache entry.

.. autoclass:: dns.resolver.CacheBase
   :members:

.. autoclass:: dns.resolver.Cache
   :members:

.. autoclass:: dns.resolver.LRUCache
   :members:

.. autoclass:: dns.resolver.CacheStatistics
   :members:
