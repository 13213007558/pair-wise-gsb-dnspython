.. _resolver-caching:

Resolver Caching Classes
========================

The dnspython resolver does not cache by default, but caching can be
enabled by creating a cache and assigning it to the resolver's *cache*
attribute.  If a cache has been configured, the resolver caches both
positive and negative responses.  The cache respects the DNS TTL of
the data, and will not return expired entries.

Negative responses are cached according to RFC 2308.  An NXDOMAIN is
cached by query name only, as a name that does not exist does not
exist for any query type, while a NODATA response (NOERROR with no
answer) is cached by query name, query type, and query class.  The
expiration time of a negative cache entry is the negative caching TTL
of the applicable SOA, i.e. the minimum of the SOA's TTL and its
MINIMUM field; negative responses without an applicable SOA are not
cached.  CNAME and DNAME chain TTLs are only applied to positive
answers, and are not mixed into the negative caching TTL.

When multiple threads resolve the same question concurrently, only
one of them queries the nameservers; the others wait and then use
the cached result.

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
