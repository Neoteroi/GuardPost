"""
This example illustrates how to validate JWTs signed with EC keys (ES256, ES384,
ES512), using an in-memory JWKS built from generated EC key pairs.
"""
import asyncio
import base64

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from guardpost.jwks import JWKS, InMemoryKeysProvider
from guardpost.jwts import AsymmetricJWTValidator


def _int_to_base64url(value: int, length: int) -> str:
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def generate_ec_key_pair(curve, kid: str, alg: str, crv: str):
    """Generate an EC private key and return (private_pem, jwk_dict)."""
    private_key = ec.generate_private_key(curve())
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_numbers = private_key.public_key().public_numbers()
    key_size = (curve().key_size + 7) // 8
    jwk_dict = {
        "kty": "EC",
        "kid": kid,
        "alg": alg,
        "crv": crv,
        "x": _int_to_base64url(pub_numbers.x, key_size),
        "y": _int_to_base64url(pub_numbers.y, key_size),
    }
    return private_pem, jwk_dict


async def main():
    # 1. Generate EC key pairs for P-256 (ES256), P-384 (ES384), and P-521 (ES512)
    key_configs = [
        (ec.SECP256R1, "key-p256", "ES256", "P-256"),
        (ec.SECP384R1, "key-p384", "ES384", "P-384"),
        (ec.SECP521R1, "key-p521", "ES512", "P-521"),
    ]
    private_keys = {}
    jwk_list = []
    for curve, kid, alg, crv in key_configs:
        private_pem, jwk_dict = generate_ec_key_pair(curve, kid, alg, crv)
        private_keys[kid] = (private_pem, alg)
        jwk_list.append(jwk_dict)

    # 2. Build an in-memory JWKS and configure the validator for all EC algorithms
    jwks = JWKS.from_dict({"keys": jwk_list})
    keys_provider = InMemoryKeysProvider(jwks)
    validator = AsymmetricJWTValidator(
        valid_issuers=["https://example.com"],
        valid_audiences=["my-api"],
        keys_provider=keys_provider,
        algorithms=["ES256", "ES384", "ES512"],
    )

    # 3. Sign and validate a JWT for each key
    for kid, (private_pem, alg) in private_keys.items():
        payload = {
            "iss": "https://example.com",
            "aud": "my-api",
            "sub": f"user-signed-with-{kid}",
        }
        token = jwt.encode(
            payload,
            private_pem,
            algorithm=alg,
            headers={"kid": kid},
        )

        claims = await validator.validate_jwt(token)

        assert claims["sub"] == f"user-signed-with-{kid}"
        print(f"EC JWT ({alg}) validated successfully. Claims:", claims)


asyncio.run(main())
