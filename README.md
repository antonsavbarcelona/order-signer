# order-signer

Small internal HTTP service that signs Hyperliquid L1 actions with the official
`hyperliquid-python-sdk`.

## Endpoints

- `GET /health`
- `POST /sign-l1-action`

`/sign-l1-action` requires:

```http
Authorization: Bearer <SIGNER_SERVICE_TOKEN>
```

Request:

```json
{
  "private_key_hex": "02534207383b33f5f34e09c1c69cb2642f906cef2ef24f91daa90b6b5b71f284",
  "action": {
    "type": "order",
    "orders": [
      {
        "a": 0,
        "b": true,
        "p": "10",
        "s": "1",
        "r": false,
        "t": { "limit": { "tif": "Ioc" } },
        "c": "0x00000000000000000000000000000000"
      }
    ],
    "grouping": "na"
  },
  "nonce": 1782662570565,
  "is_mainnet": false,
  "vault_address": null,
  "expires_after": null
}
```

Response:

```json
{
  "r": "0x...",
  "s": "0x...",
  "v": 28,
  "signer_address": "0xcdadea5edfcaa8be1ec30d98ba4e42d7bd0328d5"
}
```

## Local Run

```bash
pip install -r requirements.txt
SIGNER_SERVICE_TOKEN=dev-token uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Railway

Set:

```env
SIGNER_SERVICE_TOKEN=<shared-internal-token>
PORT=8000
```

Keep this service internal. It receives private keys for signing and must not be
publicly reachable.
