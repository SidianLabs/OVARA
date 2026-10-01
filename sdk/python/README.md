# ovara-sdk

Python SDK for the Ovara Runtime Gateway.

## Usage

```python
import asyncio
from ovara_sdk import OvaraClient, ActionRequest

async def main():
    client = OvaraClient(base_url="http://localhost:8080", api_key="sk_...")
    try:
        # Advisory check: the gateway returns a DecisionResponse JSON object.
        decision = await client.check(
            ActionRequest(
                action_type="shell",
                resource="shell:ls",
                environment="local",
            )
        )
        print(decision["decision"])  # "allow" | "deny" | "escalate"
    finally:
        await client.aclose()

asyncio.run(main())
```

## Receipts

Gateway decision receipts (`GET /v1/receipts/{id}`) are HMAC-signed
server-side and are not client-verifiable. The receipt-verification
helpers (`verify_receipt`, `compute_receipt_digest`) verify *proxy*
receipts — the ed25519 `sig_v1` chain produced by the Ovara egress proxy
(`proxy/internal/receipts`) — using the proxy's distributed public key.

## Development

```sh
pip install -e ".[dev]"
pytest
```
