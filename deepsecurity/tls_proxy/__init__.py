"""Opt-in TLS inspection (v3.0).

This module is OFF by default and stays off until the operator explicitly
enables it. TLS inspection requires installing a local Certificate
Authority into the Trusted Root store and routing the laptop's outbound
TLS through a local proxy. Most browsers + apps will trust the local
CA after the install; **certificate-pinned apps will refuse** and
their traffic must be proxied via pass-through.

Enable:
    deepsec tls install-ca
    deepsec tls start

Disable + clean up:
    deepsec tls stop
    deepsec tls uninstall-ca

Default upstream is mitmproxy on 127.0.0.1:8080. We don't ship
mitmproxy itself — it's pulled in via the heavy ``[tls-proxy]`` extra.
"""

from __future__ import annotations
