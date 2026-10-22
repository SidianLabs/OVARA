package main

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type tarEntry struct {
	name, link, body string
	typ              byte
	mode             int64
}

func buildTar(t *testing.T, entries []tarEntry) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: e.mode, Size: int64(len(e.body))}
		if h.Mode == 0 {
			h.Mode = 0o644
		}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return &buf
}

func TestExtractTree_RoundTripKeepsLinksAsLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	dir := filepath.Join(t.TempDir(), "ws")
	buf := buildTar(t, []tarEntry{
		{name: "src/", typ: tar.TypeDir, mode: 0o755},
		{name: "src/main.go", typ: tar.TypeReg, body: "package main\n"},
		{name: "run.sh", typ: tar.TypeReg, body: "#!/bin/sh\n", mode: 0o4755}, // set-uid bit dropped
		{name: "etc-link", typ: tar.TypeSymlink, link: "/etc/passwd"},
	})
	if err := extractTree(buf, dir, treeMaxBytes, treeMaxEntries); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "src", "main.go")); err != nil || string(b) != "package main\n" {
		t.Fatalf("src/main.go: %q %v", b, err)
	}
	st, err := os.Stat(filepath.Join(dir, "run.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSetuid != 0 {
		t.Error("the set-uid bit came back")
	}
	lst, err := os.Lstat(filepath.Join(dir, "etc-link"))
	if err != nil || lst.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("etc-link is not a link: %v %v", lst, err)
	}
	if target, _ := os.Readlink(filepath.Join(dir, "etc-link")); target != "/etc/passwd" {
		t.Errorf("link target %q", target)
	}
}

// Every way a hostile tar could write outside the directory, or exhaust the
// host, is refused.
func TestExtractTree_RefusesHostileEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks")
	}
	outside := t.TempDir()
	for _, c := range []struct {
		name    string
		entries []tarEntry
		want    string
	}{
		{"absolute", []tarEntry{{name: "/etc/evil", typ: tar.TypeReg, body: "x"}}, "refusing"},
		{"dot-dot", []tarEntry{{name: "../evil", typ: tar.TypeReg, body: "x"}}, "refusing"},
		{"inner dot-dot", []tarEntry{{name: "a/../../evil", typ: tar.TypeReg, body: "x"}}, "refusing"},
		{"through a link", []tarEntry{
			{name: "out", typ: tar.TypeSymlink, link: outside},
			{name: "out/evil", typ: tar.TypeReg, body: "x"},
		}, "not a directory"},
		{"twice", []tarEntry{
			{name: "f", typ: tar.TypeReg, body: "1"},
			{name: "f", typ: tar.TypeReg, body: "2"},
		}, "f"},
		{"device", []tarEntry{{name: "null", typ: tar.TypeChar}}, "entry type"},
		{"fifo", []tarEntry{{name: "p", typ: tar.TypeFifo}}, "entry type"},
		{"hard link", []tarEntry{{name: "h", typ: tar.TypeLink, link: "/etc/shadow"}}, "entry type"},
		{"backslash", []tarEntry{{name: `a\..\..\evil`, typ: tar.TypeReg, body: "x"}}, "refusing"},
	} {
		dir := filepath.Join(t.TempDir(), "ws")
		err := extractTree(buildTar(t, c.entries), dir, treeMaxBytes, treeMaxEntries)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one mentioning %q", c.name, err, c.want)
		}
	}
	if entries, _ := os.ReadDir(outside); len(entries) != 0 {
		t.Fatalf("something was written outside: %v", entries)
	}
}

func TestExtractTree_Limits(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ws")
	big := buildTar(t, []tarEntry{{name: "a", typ: tar.TypeReg, body: strings.Repeat("x", 100)}})
	if err := extractTree(big, dir, 50, treeMaxEntries); err == nil {
		t.Error("more bytes than the limit were unpacked")
	}
	dir2 := filepath.Join(t.TempDir(), "ws")
	many := buildTar(t, []tarEntry{
		{name: "a", typ: tar.TypeReg, body: "1"}, {name: "b", typ: tar.TypeReg, body: "2"}, {name: "c", typ: tar.TypeReg, body: "3"},
	})
	if err := extractTree(many, dir2, treeMaxBytes, 2); err == nil {
		t.Error("more entries than the limit were unpacked")
	}
	// the destination must be new
	if err := extractTree(buildTar(t, nil), t.TempDir(), treeMaxBytes, treeMaxEntries); err == nil {
		t.Error("unpacked into an existing directory")
	}
}
