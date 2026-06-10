# Ovara Policy Adapters

Bridge adapters for mapping external policy formats to Ovara's policy model.

## OPA (Rego) Adapter

Translates Rego policies to Ovara policy JSON format.

Status: planned

## Cedar Adapter

Translates AWS Cedar policies to Ovara policy JSON format.

Status: planned

## Custom Adapter

JSON schema for third-party policy format integration.

```json
{
  "source": "external-system",
  "mapping": {
    "action": "$.operation",
    "resource": "$.target",
    "effect": "$.outcome"
  }
}
```
