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


SIG_V1_PREFIX = "sig_v1:"
SIG_V2_PREFIX = "sig_v2:"
# Separates v2 receipt signatures from every other use of the key
# (domainV2 in proxy/internal/receipts/chain.go).
_RECEIPT_DOMAIN_V2 = b"ovara-proxy-receipt-v2\n"


def _receipt_canonical_v1(r: PortableReceipt) -> str:
    """Mirrors Receipt.canonicalV1() in proxy/internal/receipts/chain.go:
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


def _receipt_canonical_v2(r: PortableReceipt) -> bytes:
    """Mirrors Receipt.canonicalV2(): the domain separator, then each
    field as a length-prefixed name and a length-prefixed value (lengths
    are big-endian uint32 byte counts of the UTF-8 encoding), in a fixed
    order. reasons is encoded as its count, then each reason
    length-prefixed. Raises UnicodeEncodeError on a lone surrogate, which
    no JSON line the proxy writes can decode to."""
    out = bytearray(_RECEIPT_DOMAIN_V2)

    def lp(s: str) -> None:
        b = s.encode("utf-8")
        out.extend(len(b).to_bytes(4, "big"))
        out.extend(b)

    def field(name: str, val: str) -> None:
        lp(name)
        lp(val)

    reasons = r.reasons or []
    field("v", str(r.v or 0))
    field("receipt_id", r.receipt_id)
    field("session_id", r.session_id)
    field("timestamp", str(_rfc3339_to_unix_nano(r.timestamp)))
    field("method", r.method)
    field("url", r.url)
    field("decision", r.decision)
    field("status", str(r.status))
    field("approval_id", r.approval_id or "")
    field("phase", r.phase or "")
    field("outcome", r.outcome or "")
    field("attempt_id", r.attempt_id or "")
    field("agent", r.agent or "")
    field("rule", r.rule or "")
    field("policy_hash", r.policy_hash or "")
    field("approver", r.approver or "")
    field("req_bytes", str(r.req_bytes or 0))
    field("resp_bytes", str(r.resp_bytes or 0))
    field("body_sha256", r.body_sha256 or "")
    field("reasons", str(len(reasons)))
    for s in reasons:
        lp(s)
    field("kid", r.kid or "")
    field("prev_hash", r.prev_hash)
    return bytes(out)


def _receipt_has_v2_fields(r: PortableReceipt) -> bool:
    """Any field a v1 signature does not cover is set (hasV2Fields)."""
    return bool(
        r.phase or r.outcome or r.attempt_id or r.agent or r.rule
        or r.policy_hash or r.approver or r.req_bytes or r.resp_bytes
        or r.body_sha256 or r.reasons or r.kid
    )


def _receipt_version(r: PortableReceipt) -> int:
    """The canonical form a receipt claims: 2 when anything about it says
    v2 (the v field, a "sig_v2:" signature, or a field only v2 signs),
    1 otherwise."""
    if r.v == 2 or (r.signature or "").startswith(SIG_V2_PREFIX) or _receipt_has_v2_fields(r):
        return 2
    return 1


def _receipt_types_ok(r: PortableReceipt) -> bool:
    """The JSON types the proxy writes. A bool is not an int here, and a
    float is not an int, even where str() would happen to match."""
    def is_int(x: object) -> bool:
        return isinstance(x, int) and not isinstance(x, bool)

    strs = [r.receipt_id, r.session_id, r.timestamp, r.method, r.url, r.decision,
            r.prev_hash, r.signature]
    opt_strs = [r.approval_id, r.phase, r.outcome, r.attempt_id, r.agent, r.rule,
                r.policy_hash, r.approver, r.body_sha256, r.kid]
    if not all(isinstance(x, str) for x in strs):
        return False
    if not all(x is None or isinstance(x, str) for x in opt_strs):
        return False
    if not is_int(r.status):
        return False
    if not all(x is None or is_int(x) for x in (r.v, r.req_bytes, r.resp_bytes)):
        return False
    if r.reasons is not None and not (
        isinstance(r.reasons, list) and all(isinstance(x, str) for x in r.reasons)
    ):
        return False
    return True


def receipt_key_id(public_key_hex: str) -> str:
    """The id a v2 receipt names its signing key by (``kid``): the first
    16 hex digits of the SHA-256 of the raw public key (KeyID in
    proxy/internal/receipts/keys.go)."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:16]


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
    """Verify one Ovara *proxy* receipt against the proxy's public key.

    The version is chosen by the signature prefix and the ``v`` field, and
    they must agree:

    - "sig_v2:" requires ``v`` == 2 and ``kid`` naming ``public_key_hex``;
      the signature covers the v2 length-prefixed encoding of every field.
    - "sig_v1:" requires no ``v`` and no v2-only field (a v1 signature does
      not cover them, so a receipt carrying them is refused rather than
      verified on the fields it happens to sign).

    This checks a single receipt. Chain properties — prev_hash links, v1
    receipts never following v2 ones, outcomes naming an earlier attempt,
    key validity windows — are checked by ``ovara log --verify-only``.

    The public key is distributed by the proxy alongside the receipt
    chain. Gateway decision receipts are HMAC-signed and are NOT
    verifiable with this function — use GET /v1/receipts/{id}.
    """
    if not receipt.signature or not public_key_hex:
        return False
    if not _receipt_types_ok(receipt):
        return False
    sig = receipt.signature
    # Exactly 64 hex-encoded bytes after the prefix, as Go's hex decoder
    # and ed25519 require (bytes.fromhex alone would also skip spaces).
    if not re.fullmatch(r"sig_v[12]:[0-9a-fA-F]{128}", sig):
        return False
    try:
        if sig.startswith(SIG_V2_PREFIX):
            if receipt.v != 2:
                return False
            if receipt.kid != receipt_key_id(public_key_hex):
                return False
            return _ed25519_verify_bytes(
                public_key_hex, _receipt_canonical_v2(receipt), sig[len(SIG_V2_PREFIX):]
            )
        if sig.startswith(SIG_V1_PREFIX):
            if receipt.v is not None or _receipt_has_v2_fields(receipt):
                return False
            return _ed25519_verify_bytes(
                public_key_hex, _receipt_canonical_v1(receipt).encode("utf-8"),
                sig[len(SIG_V1_PREFIX):],
            )
    except (ValueError, UnicodeEncodeError):
        return False
    return False


def compute_receipt_digest(receipt: PortableReceipt) -> str:
    """SHA-256 (hex) of the receipt's canonical signing payload, v1 or v2
    as the receipt claims (see ``verify_receipt``)."""
    if _receipt_version(receipt) == 2:
        return hashlib.sha256(_receipt_canonical_v2(receipt)).hexdigest()
    return hashlib.sha256(_receipt_canonical_v1(receipt).encode("utf-8")).hexdigest()


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
    return _ed25519_verify_bytes(public_key_hex, message.encode(), signature_hex)


def _ed25519_verify_bytes(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        signature_bytes = bytes.fromhex(signature_hex)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, message)
        return True
    except (ValueError, InvalidSignature):
        return False
