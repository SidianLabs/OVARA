package main

import "testing"

// The demo is the product's front door; if it stops working end to end
// (allow → pause → human approve → block → verified receipts) a new user's
// first experience breaks. cmdDemo returns an error on any deviation from
// the expected story.
func TestDemoEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end demo skipped in -short mode")
	}
	t.Chdir(t.TempDir()) // cmdDemo changes directory; restore it afterwards
	if err := cmdDemo(); err != nil {
		t.Fatalf("demo failed: %v", err)
	}
}
