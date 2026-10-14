//go:build linux

package main

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCapToApprovalTTL(t *testing.T) {
	dir := t.TempDir()
	if _, err := deploy(dir, "0", false); err != nil {
		t.Fatal(err)
	}
	if got := capToApprovalTTL(dir, time.Hour); got != 10*time.Minute {
		t.Fatalf("default TTL: got %s", got)
	}
	if got := capToApprovalTTL(dir, time.Minute); got != time.Minute {
		t.Fatalf("a shorter wait is kept: got %s", got)
	}
	setJSON(t, filepath.Join(dir, "config.json"), map[string]any{"approval_pending_ttl_secs": 7200})
	if got := capToApprovalTTL(dir, time.Hour); got != time.Hour {
		t.Fatalf("raised TTL: got %s", got)
	}
	setJSON(t, filepath.Join(dir, "config.json"), map[string]any{"approval_pending_ttl_secs": -1})
	if got := capToApprovalTTL(dir, 5*time.Hour); got != 5*time.Hour {
		t.Fatalf("expiry off: got %s", got)
	}
}
