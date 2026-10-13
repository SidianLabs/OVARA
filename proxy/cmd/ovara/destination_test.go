package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// A look-alike host leads with a trusted name; the approval must say
// plainly who receives the request.
func TestPrintApproval_ShowsWhereItReallyGoes(t *testing.T) {
	var out bytes.Buffer
	printApproval(&out, pendingApproval{ApprovalID: "a1", Resource: "POST https://api.github.com.attacker-cdn.io/repos/acme/app/pulls"})
	want := "destination:    → to attacker-cdn.io (host api.github.com.attacker-cdn.io; not a default-trusted host)"
	if !strings.Contains(out.String(), want) {
		t.Fatalf("missing %q in:\n%s", want, out.String())
	}
	out.Reset()
	printApproval(&out, pendingApproval{ApprovalID: "a2", Resource: "GET https://pypi.org/simple/x/"})
	if !strings.Contains(out.String(), "→ to pypi.org (a default-trusted host)") {
		t.Fatalf("trusted host not said so:\n%s", out.String())
	}
	out.Reset()
	printApproval(&out, pendingApproval{ApprovalID: "a3", Resource: "commit:proj (1 files, tree 0123)"})
	if strings.Contains(out.String(), "destination:") {
		t.Fatalf("a commit-back has no network destination:\n%s", out.String())
	}
}

func TestDestinationOf(t *testing.T) {
	cases := []struct {
		resource, domain, host string
		trusted                bool
		note                   string
	}{
		{"GET https://api.github.com/repos", "github.com", "api.github.com", true, ""},
		{"POST https://api.github.com.attacker-cdn.io/x", "attacker-cdn.io", "api.github.com.attacker-cdn.io", false, ""},
		{"GET https://Docs.Example.CO.UK:443/a?b", "example.co.uk", "docs.example.co.uk", false, ""},
		{"GET https://evil.github.io/x", "evil.github.io", "evil.github.io", false, ""},
		{"GET https://g%D1%96thub.com/", "g%d1%96thub.com", "g%d1%96thub.com", false, "non-ASCII"},
		{"GET https://xn--gthub-n4a.com/", "xn--gthub-n4a.com", "xn--gthub-n4a.com", false, "non-ASCII"},
		{"POST https://10.0.0.5:8443/x", "10.0.0.5", "10.0.0.5", false, "IP address"},
		{"CONNECT UNAUTH github.com:443", "github.com", "github.com", true, ""},
		{"GET https://user:pw@example.com/", "example.com", "example.com", false, ""},
	}
	for _, c := range cases {
		d, ok := destinationOf(c.resource)
		if !ok || d.Domain != c.domain || d.Host != c.host || d.Trusted != c.trusted || !strings.Contains(d.Note, c.note) || (c.note == "" && d.Note != "") {
			t.Errorf("%s: %+v (ok=%v)", c.resource, d, ok)
		}
	}
	for _, r := range []string{"commit:proj (1 files)", "shell:rm -rf x", "npm:left-pad@1.3.0", "weird", ""} {
		if d, ok := destinationOf(r); ok {
			t.Errorf("%q has no network destination, got %+v", r, d)
		}
	}
}

// The page names the receiving domain on its own and says whether it is a
// host Ovara trusts by default.
func TestUI_PendingNamesTheDestination(t *testing.T) {
	_, h := newUI(t, pendingApproval{ApprovalID: "a1", Resource: "POST https://api.github.com.attacker-cdn.io/x"})
	rec := call(h, "GET", "/api/pending", "127.0.0.1", "Bearer tok")
	var items []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &items); err != nil || len(items) != 1 {
		t.Fatalf("pending: %v %s", err, rec.Body.String())
	}
	it := items[0]
	if it["destination"] != "attacker-cdn.io" || it["destination_trusted"] == true ||
		!strings.Contains(it["destination_note"].(string), "not a default-trusted host") {
		t.Fatalf("destination fields: %v", it)
	}
}
