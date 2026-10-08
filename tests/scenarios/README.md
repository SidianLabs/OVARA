# User scenarios

End-to-end checks of Ovara as a person actually uses it, run against the
real `ovara` binary in a Linux container:

- everyday work with no prompts: `pip install`, `npm install`, `git clone`,
  Node 24 `fetch()`, Python `requests`, a 47 MB download
- things that must be stopped: a paste site, a request-capture site, a `GET`
  that carries a body or a huge query, even to a trusted host
- the human in the loop: pause, approve, deny, a `git push` pausing, and an
  unanswered approval timing out
- keys stay with Ovara: the agent's environment has none, an injected key
  reaches the upstream, and an echoed copy is scrubbed
- policy edits apply to the running gateway without a restart
- the browser approval page: token required, DNS-rebinding Host refused
- the receipt chain verifies, an edited receipt is detected, and a restart
  keeps working

```bash
tests/scenarios/run.sh        # needs Docker and internet
```

Some steps wait on real timeouts, so it takes a few minutes. A step that
depends on a third-party site being reachable (httpbin.org) is reported as
SKIP, not PASS, when the site is down.

These scenarios found four real bugs that unit tests had not (a shield that
quarantined normal agents, hot reload that never ran, forced "pauses" that
could never be approved, and a receipt written after the response).
