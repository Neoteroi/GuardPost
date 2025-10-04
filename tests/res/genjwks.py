"""
Functions to generate RSA keys and JWKS.
"""

import base64
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def int_to_base64(value: int):
    result = value.to_bytes((value.bit_length() + 7) // 8, "big", signed=False)
    return base64.urlsafe_b64encode(result).decode()


def generate_jwk(kid: str, key_size: int = 2048, public_exponent: int = 65537):
    private_key = rsa.generate_private_key(
        public_exponent=public_exponent,
        key_size=key_size,
        backend=default_backend(),
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with open(f"{kid}.pem", mode="wb") as private_key_file:
        private_key_file.write(pem)

    public_key = private_key.public_key()
    public_numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "kid": kid,
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }


def generate_jwks():
    data = {"keys": [generate_jwk(str(i)) for i in range(5)]}

    with open("jwks.json", encoding="utf8", mode="wt") as output_file:
        output_file.write(json.dumps(data, indent=4, ensure_ascii=False))


if __name__ == "__main__":
    generate_jwks()
