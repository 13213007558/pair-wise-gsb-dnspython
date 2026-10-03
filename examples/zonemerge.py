#!/usr/bin/env python3

"""Three-way zone merge example.

Two automation branches have independently modified the same zone.
When they touch different hosts, the merge is automatic; when they
change the same RRset (here, the TTL of www), the conflict is reported
with all three values and must be resolved by the caller.
"""

import dns.zone
import dns.zonemerge

base_text = """$ORIGIN example.com.
@ 300 IN SOA ns1 admin 1 3600 600 86400 300
@ 300 IN NS ns1
www 300 IN A 192.0.2.1
"""

# Branch "ours" adds host1; branch "theirs" adds host2.
ours_text = base_text + "host1 300 IN A 192.0.2.10\n"
theirs_text = base_text + "host2 300 IN A 192.0.2.20\n"

base = dns.zone.from_text(base_text, "example.com.")
ours = dns.zone.from_text(ours_text, "example.com.")
theirs = dns.zone.from_text(theirs_text, "example.com.")

result = dns.zonemerge.merge_zones(base, ours, theirs)
assert result.ok
print("=== merged zone (different hosts merge cleanly) ===")
print(result.zone.to_text())

# The merged zone can be written as master file text and read back
# without losing anything.
reread = dns.zone.from_text(result.zone.to_text(), "example.com.")
assert reread == result.zone

# Now both branches change the TTL of the same RRset differently.
ours2 = dns.zone.from_text(base_text.replace("www 300", "www 400"), "example.com.")
theirs2 = dns.zone.from_text(base_text.replace("www 300", "www 500"), "example.com.")

result = dns.zonemerge.merge_zones(base, ours2, theirs2)
if not result.ok:
    print("=== conflicts (same RRset changed on both sides) ===")
    for conflict in result.conflicts:
        print(conflict)
