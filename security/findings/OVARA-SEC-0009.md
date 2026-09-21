# OVARA-SEC-0009 — Response trailers forwarded unscrubbed

**Severity:** MEDIUM
**Component:** proxy/internal/proxy/proxy.go pipeBody + scrubReader path
**Status:** CONFIRMED LIVE (exotic-reflector test)

## Evidence
`pipeBody` drains `res.Trailer` and forwards it via `Write` calls, but
those bytes do NOT pass through `scrubReader` (which wraps only
`res.Body`). Live test: TLS reflector announcing + sending
`X-Trailer-Secret` → secret reached the agent unredacted, while body +
header paths were scrubbed.

## Root cause
The scrub boundary was drawn at body+headers; trailers are a third
reflection surface the transport forwards verbatim.

## Proposed fix
Run `res.Trailer` values through `creds.Scrub` before forwarding (both
Announce headers and Trailer values). Same for any other forwarded
surfaces (alt-svc strings, etc.).

## Regression test
Reflector that echoes the secret in a trailer → assert `[REDACTED]`
in trailer received by client.

## Residual risk
None — trailers are bounded key-value sets, cheaper to scrub than the
streaming body.
