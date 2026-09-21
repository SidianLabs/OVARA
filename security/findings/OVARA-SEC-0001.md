# OVARA-SEC-0001 — Compressed/encoded responses bypass credential scrub

**Severity:** HIGH
**Component:** proxy/internal/proxy/scrub.go, proxy.go:505-528
**Status:** CONFIRMED LIVE (clean-room audit)

## Preconditions
A credential binding exists for a host whose response can reflect request
data (httpbin /headers, debug endpoints, request-bin services, error
echoes). The agent explicitly sends `Accept-Encoding` — normal client
behavior (`curl --compressed`, browsers, most HTTP libs).

## Reproduction (verified live)
1. Binding `httpbin.org → Authorization: Bearer SUPER_SECRET_TOKEN_XYZ`
2. `curl --compressed -x proxy https://httpbin.org/gzip`
3. Response body contains `"Authorization": "Bearer SUPER_SECRET_TOKEN_XYZ"` — full credential returned to the agent.

Also verified on a local TLS reflector: `/gzip` leaked;
`/b64` (base64) and `/urlenc` (percent) variants leaked as expected
server-side transforms. Exact-byte secrets were correctly `[REDACTED]`
in body, headers, JSON, 1-byte-split streams, 5MB bodies, error pages,
and the `X-Echo` header of a 302.

Additional confirmed variants (code + reviewer):
- `resp.Trailer` forwarded verbatim — trailer echo unscrubbed (proxy.go:526).
- Forwarded `Content-Length` is stale after redaction → malformed
  response (client hang/chop).
- Range/paginated responses: each request's window holds only a secret
  fragment → EOF flush emits fragments verbatim → agent reassembles.

## Root cause
Go's transport only auto-decompresses when IT added `Accept-Encoding`.
When the agent supplies the header, upstream returns compressed bytes and
the scrubber's `bytes.ReplaceAll` sees ciphertext. Encodings the agent can
request: gzip, deflate, br, zstd.

## Security impact
The I2 invariant ("agent cannot obtain a brokered credential") is defeated
on any bound host that both reflects and compresses — a standard,
unremarkable pair of behaviors.

## Proposed fix
1. For credentialed requests (len(injected)>0): `r.Header.Del("Accept-Encoding")`
   before RoundTrip — compliant servers send identity.
2. Belt-and-suspenders: if a credentialed response still arrives with
   `Content-Encoding` != identity, decompress (stdlib gzip/deflate;
   reject br/zstd with 502 — better fail-closed than leak) then scrub.
3. Scrub `resp.Trailer` with the same secret set.
4. `w.Header().Del("Content-Length")` whenever scrubbing is active.
5. Scrub secret fragments at EOF (head/tail ≥ min(8,len/2)) to blunt
   Range-reassembly; document residual (arbitrary server-side transforms
   like base64 can never be exhaustively caught — the real control is
   not binding reflector-capable hosts).

## Regression test
Existing `scrub_test.go` + new cases: gzipped body containing secret,
trailer echo, two-request Range split.

## Residual risk
Server-side transforms (base64/hex/rot13/custom) remain uncatchable —
accepted-risk, documented; operators must not bind echoing services.
