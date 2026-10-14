package receipts

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// A receipt line is read from disk anyone with the directory may have
// touched. parseLine never panics on it; and a valid v2 line with any one
// byte changed (every position is tried, with the fuzzed change) no longer
// verifies, so no byte of a line sits outside what the signature covers.
func FuzzReceiptLine(f *testing.F) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	ring := SingleKey(pub)
	kid := KeyID(pub)

	f.Add("GET", "https://pypi.org/simple/x/", "allow", 200, "rule", int64(0), uint8(1))
	f.Add("POST", "https://api.github.com/repos/a/b/pulls", "escalate", 0, "", int64(123456789), uint8(0x20))
	f.Add("CONNECT", "evil.example:443", "deny", 403, "r\"q\\<>& ", int64(-1), uint8(0xff))
	f.Add("", "", "", -1, "\xff\xfe", int64(1)<<40, uint8(0x01))
	f.Add("GET", "{\"v\":2}", "allow", 1, "x", int64(5), uint8(0x0a))
	f.Fuzz(func(t *testing.T, method, url, decision string, status int, rule string, nanos int64, flip uint8) {
		_, _ = parseLine([]byte(url))

		r := &Receipt{
			V: 2, ReceiptID: "rcpt_0011223344556677", SessionID: "s",
			Timestamp: time.Unix(1_700_000_000, 0).Add(time.Duration(nanos % int64(time.Hour))).UTC(),
			Method:    clean(method), URL: clean(url), Decision: clean(decision), Status: status,
			Rule: clean(rule), KeyID: kid, Reasons: []string{clean(rule)},
		}
		r.Signature = sigV2Prefix + hex.EncodeToString(ed25519.Sign(key, r.canonicalV2()))
		line, err := json.Marshal(r)
		if err != nil {
			t.Skip()
		}
		verify := func(b []byte) *VerifyResult {
			res, _, _ := verifyData(append(b, '\n'), ring, Segment{})
			return res
		}
		if res := verify(line); !res.Valid {
			t.Fatalf("valid line refused (%s): %s", res.Reason, line)
		}
		if flip == 0 {
			flip = 0x20
		}
		bad := make([]byte, len(line))
		for i := range line {
			copy(bad, line)
			bad[i] ^= flip
			if res := verify(bad); res.Valid && res.Total > 0 {
				t.Fatalf("byte %d changed (%q -> %q) and the line still verifies: %s", i, line[i], bad[i], bad)
			}
		}
	})
}
