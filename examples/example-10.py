"""
This example illustrates how to validate JWTs signed with a symmetric secret key
(HMAC), using the SymmetricJWTValidator with HS256, HS384, and HS512 algorithms.
"""
import asyncio

import jwt

from guardpost.jwts import SymmetricJWTValidator


async def main():
    # The secret must be at least 64 bytes to satisfy HS512's minimum key length.
    secret = "super-secret-key-that-is-long-enough-for-all-hmac-algorithms-hs256-hs384-hs512!"

    # 1. Validate a token signed with HS256 (default)
    validator_hs256 = SymmetricJWTValidator(
        valid_issuers=["https://example.com"],
        valid_audiences=["my-api"],
        secret_key=secret,
        algorithms=["HS256"],
    )

    payload = {"iss": "https://example.com", "aud": "my-api", "sub": "user-123"}
    token_hs256 = jwt.encode(payload, secret, algorithm="HS256")

    claims = await validator_hs256.validate_jwt(token_hs256)
    assert claims["sub"] == "user-123"
    print("HS256 JWT validated successfully. Claims:", claims)

    # 2. Validate a token signed with HS384
    validator_hs384 = SymmetricJWTValidator(
        valid_issuers=["https://example.com"],
        valid_audiences=["my-api"],
        secret_key=secret,
        algorithms=["HS384"],
    )

    token_hs384 = jwt.encode(payload, secret, algorithm="HS384")
    claims = await validator_hs384.validate_jwt(token_hs384)
    print("HS384 JWT validated successfully. Claims:", claims)

    # 3. Validate a token signed with HS512
    validator_hs512 = SymmetricJWTValidator(
        valid_issuers=["https://example.com"],
        valid_audiences=["my-api"],
        secret_key=secret,
        algorithms=["HS512"],
    )

    token_hs512 = jwt.encode(payload, secret, algorithm="HS512")
    claims = await validator_hs512.validate_jwt(token_hs512)
    print("HS512 JWT validated successfully. Claims:", claims)


asyncio.run(main())
