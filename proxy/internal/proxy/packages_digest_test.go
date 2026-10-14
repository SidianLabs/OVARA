package proxy

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // npm's older integrity form, as matched by digestReader
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/iotest"
)

func sri512(b string) string {
	s := sha512.Sum512([]byte(b))
	return "sha512-" + base64.StdEncoding.EncodeToString(s[:])
}

func TestDigestReader(t *testing.T) {
	body := strings.Repeat("package bytes ", 10000)
	s1 := sha1.Sum([]byte(body)) //nolint:gosec // test of the sha1 form
	for name, want := range map[string][]string{
		"sha512":       {sri512(body)},
		"sha1":         {"sha1-" + base64.StdEncoding.EncodeToString(s1[:])},
		"one of many":  {sri512("another file"), sri512(body)},
		"unknown algo": {"md5-xxxx", sri512(body)},
	} {
		got, err := io.ReadAll(newDigestReader(iotest.OneByteReader(strings.NewReader(body)), want))
		if err != nil || string(got) != body {
			t.Errorf("%s: err=%v, %d of %d bytes", name, err, len(got), len(body))
		}
	}
	// a mismatch never delivers the whole body
	got, err := io.ReadAll(newDigestReader(strings.NewReader(body), []string{sri512("what was pinned")}))
	if !errors.Is(err, errDigestMismatch) || len(got) >= len(body) {
		t.Errorf("mismatch: err=%v, %d of %d bytes delivered", err, len(got), len(body))
	}
	// nor does a body cut short upstream
	got, err = io.ReadAll(newDigestReader(iotest.TimeoutReader(bytes.NewReader([]byte(body))), []string{sri512(body)}))
	if err == nil || len(got) >= len(body) {
		t.Errorf("upstream error: err=%v, %d bytes", err, len(got))
	}
}

// through the proxy: a pinned package with a matching digest arrives
// whole; with a different digest the connection is cut before the end.
func TestPackageGate_DigestCheckedEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name   string
		digest string
		ok     bool
	}{
		{"match", sri512("tarball"), true},
		{"mismatch", sri512("the pinned tarball"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, pg, hits := newPkgServer(t, false)
			srv.SetPackageGatePins(map[string][]string{"npm:left-pad@1.3.0": {tc.digest}})
			ps := httptest.NewServer(srv)
			defer ps.Close()
			pu, _ := url.Parse(ps.URL)
			client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
			resp, err := client.Get(leftPad)
			var body []byte
			if err == nil {
				body, err = io.ReadAll(resp.Body)
				resp.Body.Close()
			}
			if tc.ok && (err != nil || string(body) != "tarball") {
				t.Fatalf("match: err=%v body=%q", err, body)
			}
			if !tc.ok && (err == nil || string(body) == "tarball") {
				t.Fatalf("mismatch delivered: err=%v body=%q", err, body)
			}
			if pg.pkgChecks.Load() != 0 || hits.Load() != 1 {
				t.Fatalf("checks=%d hits=%d", pg.pkgChecks.Load(), hits.Load())
			}
		})
	}
}

// Under strict, a request on a registry that is neither metadata nor a
// package the gate can name is asked about, once per URL.
func TestPackageGate_UnrecognisedRegistryDownload(t *testing.T) {
	srv, pg, hits := newPkgServer(t, true, "npm:left-pad@1.3.0")
	pg.approvalStatus.Store("denied")
	u := "http://registry.npmjs.org/left-pad/-/payload.bin"
	if rec := do(srv, http.MethodGet, u); rec.Code != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("unrecognised: %d hits=%d", rec.Code, hits.Load())
	}
	if len(pg.resources) != 1 || pg.resources[0] != "download:registry.npmjs.org/left-pad/-/payload.bin" {
		t.Fatalf("asked about %v", pg.resources)
	}
	// a gem and a jar are named
	pg.pkgDecision.Store("allow")
	for u, ref := range map[string]string{
		"http://rubygems.org/gems/rails-7.1.0.gem":                                    "gem:rails@7.1.0",
		"http://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.9/slf4j-api-2.0.9.jar": "maven:org.slf4j:slf4j-api@2.0.9",
	} {
		if rec := do(srv, http.MethodGet, u); rec.Code != 200 {
			t.Fatalf("%s: %d", u, rec.Code)
		}
		if got := pg.resources[len(pg.resources)-1]; got != ref {
			t.Errorf("%s asked as %q, want %q", u, got, ref)
		}
	}
}
