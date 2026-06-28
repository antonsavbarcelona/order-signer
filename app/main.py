import hmac
import logging
import os
from typing import Any

from eth_account import Account
from fastapi import FastAPI, Header, HTTPException, status
from hyperliquid.utils.signing import sign_l1_action
from pydantic import BaseModel, Field


app = FastAPI(title="Hyperliquid Order Signer", version="0.1.0")
logger = logging.getLogger("order_signer")


class SignL1ActionRequest(BaseModel):
    private_key_hex: str = Field(min_length=64)
    action: dict[str, Any]
    nonce: int = Field(ge=0)
    is_mainnet: bool
    vault_address: str | None = None
    expires_after: int | None = None


class SignL1ActionResponse(BaseModel):
    r: str
    s: str
    v: int
    signer_address: str


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/sign-l1-action", response_model=SignL1ActionResponse)
def sign_l1_action_endpoint(
    req: SignL1ActionRequest,
    authorization: str | None = Header(default=None),
) -> SignL1ActionResponse:
    require_auth(authorization)

    private_key = normalize_private_key(req.private_key_hex)
    wallet = Account.from_key(private_key)
    signer_address = wallet.address.lower()

    logger.info(
        "sign_l1_action request signer_address=%s nonce=%s is_mainnet=%s vault_address=%s expires_after=%s action=%s",
        signer_address,
        req.nonce,
        req.is_mainnet,
        req.vault_address,
        req.expires_after,
        req.action,
    )

    try:
        signature = sign_l1_action(
            wallet,
            req.action,
            req.vault_address,
            req.nonce,
            req.expires_after,
            req.is_mainnet,
        )
    except Exception as exc:
        logger.exception(
            "sign_l1_action failed signer_address=%s nonce=%s is_mainnet=%s",
            signer_address,
            req.nonce,
            req.is_mainnet,
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Failed to sign Hyperliquid L1 action",
        ) from exc

    logger.info(
        "sign_l1_action response signer_address=%s nonce=%s r=%s s=%s v=%s",
        signer_address,
        req.nonce,
        signature["r"],
        signature["s"],
        signature["v"],
    )

    return SignL1ActionResponse(
        r=signature["r"],
        s=signature["s"],
        v=signature["v"],
        signer_address=signer_address,
    )


def require_auth(authorization: str | None) -> None:
    expected = os.environ.get("SIGNER_SERVICE_TOKEN")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SIGNER_SERVICE_TOKEN is not configured",
        )

    prefix = "Bearer "
    received = authorization[len(prefix) :] if authorization and authorization.startswith(prefix) else ""
    if not hmac.compare_digest(received, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid signer service token",
        )


def normalize_private_key(value: str) -> str:
    key = value.strip()
    if key.startswith("0x"):
        key = key[2:]
    if len(key) != 64:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="private_key_hex must be 32 bytes hex",
        )
    try:
        int(key, 16)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="private_key_hex must be valid hex",
        ) from exc
    return "0x" + key
