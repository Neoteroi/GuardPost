"""
This example illustrates how to validate JWTs signed with RSA keys (RS256),
using an in-memory JWKS built from a generated RSA key pair.
"""
import asyncio
import base64

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from guardpost.jwks import JWKS, InMemoryKeysProvider
from guardpost.jwts import AsymmetricJWTValidator


def _int_to_base64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def generate_rsa_key_pair():
    """Generate an RSA private key and return (private_pem, jwk_dict)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_numbers = private_key.public_key().public_numbers()
    jwk_dict = {
        "kty": "RSA",
        "kid": "my-rsa-key",
        "n": _int_to_base64url(pub_numbers.n),
        "e": _int_to_base64url(pub_numbers.e),
    }
    return private_pem, jwk_dict


async def main():
    # 1. Generate an RSA key pair and build an in-memory JWKS
    private_pem, jwk_dict = generate_rsa_key_pair()
    jwks = JWKS.from_dict({"keys": [jwk_dict]})
    keys_provider = InMemoryKeysProvider(jwks)

    # 2. Configure the validator for RS256
    validator = AsymmetricJWTValidator(
        valid_issuers=["https://example.com"],
        valid_audiences=["my-api"],
        keys_provider=keys_provider,
        algorithms=["RS256"],
    )

    # 3. Sign a JWT with the RSA private key
    payload = {"iss": "https://example.com", "aud": "my-api", "sub": "user-123"}
    token = jwt.encode(
        payload,
        private_pem,
        algorithm="RS256",
        headers={"kid": "my-rsa-key"},
    )

    # 4. Validate the token — returns the decoded claims on success
    claims = await validator.validate_jwt(token)

    assert claims["sub"] == "user-123"
    print("RSA JWT validated successfully. Claims:", claims)


asyncio.run(main())
