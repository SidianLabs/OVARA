# Ovara Policy Adapters

Bridge adapters for mapping external policy formats to Ovara's policy model.

Each adapter is a self-contained TypeScript package that translates one
external format into Ovara's native policy JSON. All adapters produce
the same output shape, so policies from any source can be loaded by the
runtime gateway interchangeably.

## Available Adapters

| Adapter | Format | Tests | Status |
|---------|--------|-------|--------|
| [`opa/`](opa/) | Open Policy Agent (Rego) | 11/11 passing | ✅ |
| [`cedar/`](cedar/) | AWS Cedar | 12/12 passing | ✅ |
| [`custom/`](custom/) | Custom JSON mappings | 8/8 passing | ✅ |

## Usage

Each adapter is published as a separate npm package with the same API:

```typescript
import { translateRego } from '@ovara/policy-adapter-opa';
import { translateCedar } from '@ovara/policy-adapter-cedar';
import { translateCustom } from '@ovara/policy-adapter-custom';

const rego = `package ovara.runtime
default allow = false
allow { input.action_type == "git.pull" }`;

const policy = translateRego(rego);
// policy.version: "v1-from-opa"
// policy.rules: [{ action_type: "git.pull", allow: true, ... }]
```

The output is an Ovara policy that can be written to `etc/policy.json` and
loaded by the gateway at startup (or hot-reloaded via the file watcher).

## Adapter Output Schema

All adapters produce the same Ovara policy shape:

```json
{
  "version": "v1-from-{adapter}",
  "rules": [
    {
      "action_type": "git.pull",
      "environment": "*",
      "allow": true,
      "deny": false,
      "escalate": false,
      "conditions": { "agent_id": "agt-001" },
      "description": "Translated from OPA rule 'allow' at line 4"
    }
  ]
}
```

The gateway applies rules in order; the first matching rule wins. If no
rule matches, the gateway's default behavior is to **escalate** (require
human approval).

## Building a New Adapter

To add a new adapter (e.g. for OpenFGA, Zanzibar, or a custom DSL):

1. Create a new directory under `adapters/<name>/`.
2. Add a `package.json` and `tsconfig.json` matching the existing
   adapters (see [`opa/package.json`](opa/package.json) for the template).
3. Implement a `translate<Format>()` function that returns an
   `OvaraPolicy` (see the interface in any existing adapter).
4. Write Vitest tests covering: success cases, error handling, default
   behavior, and edge cases (empty input, malformed input, missing
   fields).
5. Update this README with the new adapter row.

## Running Tests

```bash
cd adapters/opa && npx vitest run
cd adapters/cedar && npx vitest run
cd adapters/custom && npx vitest run
```

Or via the Makefile:

```bash
make test-ts
```
