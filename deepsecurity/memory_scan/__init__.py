"""Userspace memory inspection — limited but real (v3.0).

We can read the memory of any process whose token allows it (same UID
or Administrator with SeDebugPrivilege). We CANNOT inspect Protected-
Process-Light processes — those need a kernel driver. Defender covers
that slice.

What this gives us:
    - String scans inside running processes (looks for hardcoded URLs,
      DLP-style secret patterns in heap/stack).
    - Module-list dump (the loaded DLLs in a target process).
    - Decoded base-address + region-size for further analysis.

Implementation uses pure ctypes against ``OpenProcess`` /
``ReadProcessMemory`` / ``VirtualQueryEx``. No new dep.
"""

from __future__ import annotations
