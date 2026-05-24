# Threat Model

## Primary Threat Classes

- prompt injection leading to tool misuse
- agent impersonation or capability theft
- recursive authority expansion
- poisoned code or dependency execution
- unauthorized infra or financial mutations

## Design Response

- intercept before execution
- scope authority tightly
- require signed provenance
- degrade trust continuously
- preserve receipt-grade auditability

