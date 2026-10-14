package proxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// An executable or installer coming back on an allowed read is a question
// of its own; the agent gets the file only on an allow.

func fileServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/get":
			w.Header().Set("Content-Disposition", `attachment; filename="setup.exe"`)
			w.Header().Set("Content-Type", "application/octet-stream")
			fmt.Fprint(w, "MZ...")
		case "/tool.sh":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "#!/bin/sh\necho hi\n")
		case "/blob":
			w.Header().Set("Content-Type", "application/x-msdownload")
			fmt.Fprint(w, "MZ...")
		case "/data.csv":
			w.Header().Set("Content-Type", "text/csv")
			fmt.Fprint(w, "a,b\n")
		case "/src.tar.gz":
			w.Header().Set("Content-Disposition", `attachment; filename="src.tar.gz"`)
			w.Header().Set("Content-Type", "application/gzip")
			fmt.Fprint(w, "gz")
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDownloads_ExecutableIsAQuestion(t *testing.T) {
	srv, ag, chainFile := newActionServer(t, "allow")
	up := fileServer(t)
	host := mustHostPort(t, up.URL)
	ag.setDecision(actionDownload, "deny")

	rec := send(srv, http.MethodGet, up.URL+"/get", "", nil, nil)
	if rec.Code != 403 || rec.Body.String() == "MZ..." {
		t.Fatalf("a refused download reached the agent: %d %q", rec.Code, rec.Body.String())
	}
	c := ag.of(actionDownload)
	if len(c) != 1 || c[0].Resource != "download:"+host+"/get" || c[0].Context["download"] != "setup.exe (application/octet-stream, 5 bytes)" {
		t.Fatalf("asked %+v", c)
	}
	r := lastReceiptOf(t, chainFile)
	if r.Decision != gwDeny || !containsString(r.Reasons, "download:setup.exe") || !containsString(r.Reasons, "download_refused") || r.Phase != phaseOutcome {
		t.Fatalf("receipt: %+v", r)
	}

	ag.setDecision(actionDownload, "allow")
	rec = send(srv, http.MethodGet, up.URL+"/get", "", nil, nil)
	if rec.Code != 200 || rec.Body.String() != "MZ..." {
		t.Fatalf("an allowed download: %d %q", rec.Code, rec.Body.String())
	}
	if r := lastReceiptOf(t, chainFile); r.Decision != gwAllow || !containsString(r.Reasons, "download:setup.exe") {
		t.Fatalf("receipt: %+v", r)
	}
}

func TestDownloads_WhatCounts(t *testing.T) {
	srv, ag, _ := newActionServer(t, "allow")
	up := fileServer(t)
	ag.setDecision(actionDownload, "deny")
	for path, asked := range map[string]bool{"/tool.sh": true, "/blob": true, "/data.csv": false, "/src.tar.gz": false} {
		before := len(ag.of(actionDownload))
		rec := send(srv, http.MethodGet, up.URL+path, "", nil, nil)
		got := len(ag.of(actionDownload)) > before
		if got != asked {
			t.Errorf("%s: asked=%v, want %v", path, got, asked)
		}
		if !asked && rec.Code != 200 {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

func TestDownloads_OffUnderAnApprovedURL(t *testing.T) {
	// A GET a person approved as a URL is not asked about again: the URL
	// was in front of them.
	srv, ag, _ := newActionServer(t, "escalate")
	ag.status.Store("approved")
	up := fileServer(t)
	ag.setDecision(actionDownload, "deny")
	rec := send(srv, http.MethodGet, up.URL+"/get", "", nil, nil)
	if rec.Code != 200 || len(ag.of(actionDownload)) != 0 {
		t.Fatalf("approved URL: %d, asked %d", rec.Code, len(ag.of(actionDownload)))
	}
}
