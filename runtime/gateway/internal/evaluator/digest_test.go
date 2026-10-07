package evaluator

import (
	"strings"
	"testing"

	"ovara.runtime.gateway/internal/models"
)

func TestActionDigestBindsEveryFieldUnambiguously(t *testing.T) {
	base := func() *models.ActionRequest {
		return &models.ActionRequest{ActionType: "http.request", Resource: "POST https://a.example/x", Environment: "prod"}
	}
	d0 := actionDigest(base())

	if !strings.HasPrefix(d0, "sha256:") || len(d0) != len("sha256:")+64 {
		t.Fatalf("digest must be the full SHA-256, got %q", d0)
	}
	if actionDigest(base()) != d0 {
		t.Fatal("digest is not deterministic")
	}

	env := base()
	env.Environment = "dev"
	if actionDigest(env) == d0 {
		t.Error("environment is not bound: an approval for dev would be valid for prod")
	}

	md := base()
	md.Metadata = []byte(`{"force":true}`)
	if actionDigest(md) == d0 {
		t.Error("metadata is not bound")
	}

	// Field boundaries: moving bytes between adjacent fields must change the digest.
	a, b := base(), base()
	a.ActionType, a.Resource = "ab", "c"
	b.ActionType, b.Resource = "a", "bc"
	if actionDigest(a) == actionDigest(b) {
		t.Error("fields are concatenated without delimiting; boundaries are ambiguous")
	}
}

func TestGeneratedIDsAreFullUUIDs(t *testing.T) {
	id := generateID()
	if !strings.HasPrefix(id, "dec_") || len(id) != len("dec_")+36 {
		t.Fatalf("decision id %q is not a full UUID", id)
	}
	if generateID() == id {
		t.Fatal("ids repeat")
	}
}
