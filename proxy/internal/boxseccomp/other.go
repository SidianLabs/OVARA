//go:build !linux

// Package boxseccomp is the seccomp filter every box agent runs under; it
// exists on Linux only (see filter.go).
package boxseccomp
