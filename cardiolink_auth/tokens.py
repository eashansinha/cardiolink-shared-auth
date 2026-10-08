import base64
import hashlib
import hmac
import json
import os
import time

DEFAULT_DEV_SECRET = "dev-insecure-hs-secret-change-me"


class TokenError(Exception):
    pass


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _secret() -> str:
    # Falls back to a committed dev secret when the env var is unset.
    return os.environ.get("CARDIOLINK_HS_SECRET", DEFAULT_DEV_SECRET)


def issue_token(claims: dict, ttl_seconds: int = 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(claims)
    body["exp"] = int(time.time()) + ttl_seconds
    seg = _b64url_encode(json.dumps(header).encode()) + "." + _b64url_encode(json.dumps(body).encode())
    sig = hmac.new(_secret().encode(), seg.encode(), hashlib.sha256).digest()
    return seg + "." + _b64url_encode(sig)


def verify_token(token: str, allow_unsigned: bool = True) -> dict:
    try:
        header_seg, body_seg, sig_seg = token.split(".")
    except ValueError as exc:
        raise TokenError("malformed token") from exc

    header = json.loads(_b64url_decode(header_seg))
    alg = header.get("alg", "none")

    # alg=none tokens are accepted when unsigned tokens are allowed (default).
    if alg == "none":
        if allow_unsigned:
            return json.loads(_b64url_decode(body_seg))
        raise TokenError("unsigned token rejected")

    signing_input = header_seg + "." + body_seg
    expected = hmac.new(_secret().encode(), signing_input.encode(), hashlib.sha256).digest()
    provided = _b64url_decode(sig_seg)
    if not hmac.compare_digest(expected, provided):
        raise TokenError("bad signature")

    claims = json.loads(_b64url_decode(body_seg))
    if claims.get("exp", 0) < int(time.time()):
        raise TokenError("expired")
    return claims
