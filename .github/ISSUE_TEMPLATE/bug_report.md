---
name: Bug Report
about: Report a bug in Ovara
title: "[BUG] "
labels: ["bug", "triage"]
assignees: []
---

## Description

A clear, concise description of the bug.

## Reproduction Steps

1. `go build ...`
2. `ovara-gateway --config=...`
3. `curl ...`
4. See error

## Expected Behavior

What you expected to happen.

## Actual Behavior

What actually happened. Include logs, stack traces, and screenshots.

## Environment

- Ovara version: `git describe` or `ovara-gateway --version`
- OS: (e.g., Ubuntu 22.04, macOS 14)
- Architecture: (e.g., amd64, arm64)
- Go version: `go version`
- Node version (if relevant): `node --version`
- Deployment mode: (local, docker, k8s, helm)

## Configuration

If relevant, paste your `etc/config.json` (with secrets redacted):

```json
{
  "policy_version": "...",
  ...
}
```

## Severity

- [ ] Critical — production outage
- [ ] High — feature broken
- [ ] Medium — feature degraded
- [ ] Low — cosmetic

## Possible Cause

If you have an idea where the bug might be, share it here.

## Additional Context

Any other relevant information.
