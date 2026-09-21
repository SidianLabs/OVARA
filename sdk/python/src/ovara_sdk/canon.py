"""Canonical signed-payload encoding — byte-for-byte identical to the
gateway's internal/identity/canon.go lpBuilder.

Format:
    lp(s)    = u32be(len(utf8(s))) || utf8(s)   — strings, always present
    i64(v)   = u64be(v)                          — unix timestamps, ints
    lparr(a) = u32be(count) || lp(item)*         — string arrays

A signature over these bytes identifies exactly one semantic object:
field boundaries, array boundaries, and integers are unambiguous — no
pipe-join or %v formatting quirks.
"""

from __future__ import annotations

import struct
from typing import Iterable, Optional


def _lp(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">I", len(b)) + b


def _lparr(items: Iterable[str]) -> bytes:
    out = struct.pack(">I", 0)
    count = 0
    body = b""
    for s in items:
        body += _lp(s)
        count += 1
    return struct.pack(">I", count) + body


def _i64(v: int) -> bytes:
    return struct.pack(">Q", v & 0xFFFFFFFFFFFFFFFF)


def hop_payload(
    issuer: str,
    subject_id: str,
    audience: str,
    resource_scope: str,
    actions: Optional[Iterable[str]],
    expires_at_unix: int,
    delegated_at_unix: int,
    nonce: str,
    prev_sig_hex: str,
) -> bytes:
    """Canonical delegation-hop payload (matches validator.go hopPayload)."""
    return (
        _lp(issuer)
        + _lp(subject_id)
        + _lp(audience)
        + _lp(resource_scope)
        + _lparr(actions or [])
        + _i64(expires_at_unix)
        + _i64(delegated_at_unix)
        + _lp(nonce)
        + _lp(prev_sig_hex)
    )


def lease_payload(
    lease_id: str,
    issuer: str,
    subject: str,
    audience: str,
    allowed_actions: Optional[Iterable[str]],
    resource_scope: str,
    expiry_unix: int,
    issued_at_unix: int,
    delegation_depth: int,
) -> bytes:
    """Canonical capability-lease payload (matches validator.go leasePayload)."""
    return (
        _lp(lease_id)
        + _lp(issuer)
        + _lp(subject)
        + _lp(audience)
        + _lparr(allowed_actions or [])
        + _lp(resource_scope)
        + _i64(expiry_unix)
        + _i64(issued_at_unix)
        + struct.pack(">I", delegation_depth & 0xFFFFFFFF)
    )
