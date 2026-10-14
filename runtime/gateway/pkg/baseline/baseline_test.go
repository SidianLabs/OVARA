package baseline

import (
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	pub, priv, err := KeyGen()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"version":"org","rules":[]}`)
	sig, err := Sign(data, priv)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(data, sig, pub); err != nil {
		t.Fatal(err)
	}
	if err := Verify([]byte(`{"version":"org","rules":[ ]}`), sig, pub); err == nil {
		t.Fatal("a changed byte verified")
	}
	other, _, _ := KeyGen()
	if err := Verify(data, sig, other); err == nil {
		t.Fatal("another key verified")
	}
	for _, c := range []struct{ sig, pub string }{{"zz", pub}, {sig, "zz"}, {sig[:10], pub}, {sig, pub[:10]}} {
		if err := Verify(data, c.sig, c.pub); err == nil || strings.Contains(err.Error(), "changed") {
			t.Errorf("%q/%q: %v", c.sig, c.pub, err)
		}
	}
	if _, err := Sign(data, "not hex"); err == nil {
		t.Fatal("a bad private key signed")
	}
	if SigPath("/etc/ovara/baseline.json") != "/etc/ovara/baseline.json.sig" {
		t.Fatal(SigPath("x"))
	}
}
