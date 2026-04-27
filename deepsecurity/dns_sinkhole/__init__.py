"""Local DNS sinkhole — block known-bad domains at the resolver layer.

The laptop's system DNS is pointed at 127.0.0.1:53; our local server
forwards every query to an upstream resolver UNLESS the queried name
matches a blocklist, in which case we return NXDOMAIN (or a sinkhole
IP). Equivalent to running a personal Pi-hole.

server.py     — UDP DNS server (dnslib).
blocklists.py — fetch + cache known-bad domain lists.
"""

from __future__ import annotations
