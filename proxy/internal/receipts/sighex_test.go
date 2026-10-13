package receipts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// Found by FuzzReceiptLine: hex decoding accepts upper case, so a signature
// written "ab" also verified as "AB" and a line could be changed without
// failing verification. Only the writer's own (lower-case) spelling counts.
func TestSignatureHexMustBeLowerCase(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	ring := SingleKey(pub)
	for _, v := range []int{0, 2} {
		r := &Receipt{V: v, ReceiptID: "rcpt_1", SessionID: "s", Timestamp: time.Unix(1_700_000_000, 0).UTC(),
			Method: "GET", URL: "https://x/", Decision: "allow"}
		prefix := sigV1Prefix
		if v == 2 {
			r.KeyID = KeyID(pub)
			prefix = sigV2Prefix
			r.Signature = prefix + hex.EncodeToString(ed25519.Sign(key, r.canonicalV2()))
		} else {
			r.Signature = prefix + hex.EncodeToString(ed25519.Sign(key, []byte(r.canonicalV1())))
		}
		line, _ := json.Marshal(r)
		if res, _, _ := verifyData(append(line, '\n'), ring, Segment{}); !res.Valid {
			t.Fatalf("v%d: valid line refused: %s", v, res.Reason)
		}
		i := bytes.Index(line, []byte(prefix)) + len(prefix)
		for line[i] < 'a' || line[i] > 'f' {
			i++
		}
		line[i] -= 'a' - 'A'
		if res, _, _ := verifyData(append(line, '\n'), ring, Segment{}); res.Valid {
			t.Fatalf("v%d: upper-case signature hex verified: %s", v, line)
		}
	}
}
