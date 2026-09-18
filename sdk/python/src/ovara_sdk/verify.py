from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from .types import PortableReceipt


@dataclass
class PortableIdentity:
    id: str
    issuer: str
    subject_id: str
    owner: str
    lifecycle: str
    public_key: str
    signature: Optional[str] = None


@dataclass
class PortableLease:
    lease_id: str
    issuer: str
    subject: str
    allowed_actions: list[str]
    resource_scope: str
    expiry: int
    delegation_depth: int
    issued_at: int
    """ed25519 signature over the pipe-joined canonical lease payload,
    hex-encoded. On the gateway wire it is base64 (Go []byte marshals to
    base64 in JSON) — verify_capability_lease accepts both forms."""
    signature: str


def _go_string_slice(items: list[str]) -> str:
    """Render a []string the way Go's fmt %v does: "[a b c]". The
    gateway's lease canonical form (internal/identity/validator.go)
    uses %v for allowed_actions, so verifiers must match it exactly."""
    return "[" + " ".join(items) + "]"


def _rfc3339_to_unix_nano(ts: str) -> int:
    """Convert an RFC3339/RFC3339Nano timestamp to Unix nanoseconds,
    matching Go's time.Time.UnixNano()."""
    m = re.match(
        r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:?\d{2})?$", ts
    )
    if not m:
        return 0
    tz = (m.group(3) or "Z").replace("Z", "+00:00")
    base = datetime.fromisoformat(m.group(1) + tz)
    frac = (m.group(2) or "").ljust(9, "0")[:9]
    return int(base.timestamp()) * 1_000_000_000 + int(frac or "0")


def _receipt_canonical(r: PortableReceipt) -> str:
    """Mirrors Receipt.canonical() in proxy/internal/receipts/chain.go:
    receipt_id|session_id|unixnano|method|url|decision|status|prev_hash
    with "|approval_id" appended when approval_id is non-empty."""
    c = "|".join([
        r.receipt_id,
        r.session_id,
        str(_rfc3339_to_unix_nano(r.timestamp)),
        r.method,
        r.url,
        r.decision,
        str(r.status),
        r.prev_hash,
    ])
    if r.approval_id:
        c += "|" + r.approval_id
    return c


def _identity_canonical(identity: PortableIdentity) -> str:
    """Mirrors AgentIdentity.Digest() in identity/internal/crypto/
    identity.go: compact JSON (Go json.Marshal output — no spaces,
    fields in struct declaration order)."""
    return json.dumps(
        {
            "id": identity.id,
            "issuer": identity.issuer,
            "subject_id": identity.subject_id,
            "owner": identity.owner,
            "lifecycle": identity.lifecycle,
        },
        separators=(",", ":"),
    )


def _signature_to_hex(signature: str) -> str:
    """Normalize a signature to hex. The SDK carries hex-encoded
    signatures, but Go marshals []byte to base64 on the wire — accept
    that form too."""
    if re.fullmatch(r"[0-9a-fA-F]+", signature) and len(signature) % 2 == 0:
        return signature
    try:
        return base64.b64decode(signature).hex()
    except ValueError:
        return signature


def compute_identity_digest(identity: PortableIdentity) -> str:
    return hashlib.sha256(_identity_canonical(identity).encode()).hexdigest()


def verify_agent_identity(identity: PortableIdentity, issuer_public_key_hex: str) -> bool:
    """Verify an agent identity against a caller-supplied trusted public key.

    The ``public_key`` field embedded in the identity is never used for
    verification — doing so would let a forged identity attest itself.
    """
    if not identity.signature or not issuer_public_key_hex:
        return False

    payload = f"{identity.id}|{identity.issuer}|{identity.subject_id}|{identity.owner}|{identity.lifecycle}"
    return _ed25519_verify(issuer_public_key_hex, payload, identity.signature)


def verify_capability_lease(lease: PortableLease, issuer_public_key_hex: str) -> bool:
    """Verify a capability lease against the issuer's trusted public key.

    ``issuer_public_key_hex`` must come from a trusted source (e.g. key
    resolution by ``lease.issuer``); the lease itself carries no usable key.
    """
    if not lease.signature or not issuer_public_key_hex:
        return False

    payload = "|".join([
        lease.lease_id, lease.issuer, lease.subject,
        _go_string_slice(lease.allowed_actions), lease.resource_scope,
        str(lease.expiry), str(lease.delegation_depth), str(lease.issued_at),
    ])
    return _ed25519_verify(issuer_public_key_hex, payload, _signature_to_hex(lease.signature))


def verify_receipt(receipt: PortableReceipt, public_key_hex: str) -> bool:
    """Verify an Ovara *proxy* receipt: an ed25519 "sig_v1:<hex>" signature
    over the proxy's canonical pipe-joined payload (see PortableReceipt).

    The public key is distributed by the proxy alongside the receipt
    chain. Gateway decision receipts are HMAC-signed and are NOT
    verifiable with this function — use GET /v1/receipts/{id}.
    """
    if not receipt.signature or not public_key_hex:
        return False
    if not receipt.signature.startswith("sig_v1:"):
        return False

    return _ed25519_verify(public_key_hex, _receipt_canonical(receipt), receipt.signature[7:])


def compute_receipt_digest(receipt: PortableReceipt) -> str:
    return hashlib.sha256(_receipt_canonical(receipt).encode()).hexdigest()


def is_lease_expired(lease: PortableLease) -> bool:
    return datetime.now(timezone.utc).timestamp() > lease.expiry


def has_action(lease: PortableLease, action: str) -> bool:
    if is_lease_expired(lease):
        return False
    return action in lease.allowed_actions or "*" in lease.allowed_actions


def scope_covers(lease: PortableLease, resource: str) -> bool:
    # The gateway requires a non-empty resource_scope; an empty scope
    # covers nothing rather than everything.
    if not lease.resource_scope:
        return False
    return lease.resource_scope == "*" or lease.resource_scope == resource


def _ed25519_verify(public_key_hex: str, message: str, signature_hex: str) -> bool:
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message.encode())
        return True
    except (ValueError, InvalidSignature):
        return False
