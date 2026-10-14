package record

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A deployment made by a build from before journal v2 has sealed files with
// _sec.v 1. The sealed format did not change, so they must still open.
func TestSealedFileWrittenAsV1StillOpens(t *testing.T) {
	e := setup(t)
	s := e.signer
	raw, err := SealFile("idregistry", s, []byte(`{"a":1}`), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var sf SealedFile
	if err := json.Unmarshal(raw, &sf); err != nil {
		t.Fatal(err)
	}
	if sf.Sec.V != 1 {
		t.Fatalf("new sealed files must keep _sec.v 1, got %d", sf.Sec.V)
	}
	for _, v := range []int{1, 2} {
		sf.Sec.V = v
		b, _ := json.Marshal(sf)
		path := filepath.Join(t.TempDir(), "f.json")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := OpenSealedFile("idregistry", path, s.Domain(), e.resolve, Floor{}); err != nil {
			t.Fatalf("_sec.v %d: %v", v, err)
		}
	}
	sf.Sec.V = 3
	b, _ := json.Marshal(sf)
	path := filepath.Join(t.TempDir(), "f.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := OpenSealedFile("idregistry", path, s.Domain(), e.resolve, Floor{}); err == nil {
		t.Fatal("an unknown _sec version must be refused")
	}
}
