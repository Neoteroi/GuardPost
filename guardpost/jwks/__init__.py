import base64
from abc import ABC, abstractmethod
from typing import List, TypedDict

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers


class JWK(TypedDict):
    n: str
    e: str
    kid: str


class JWKS(TypedDict):
    keys: List[JWK]


class KeysProvider(ABC):
    @abstractmethod
    async def get_keys(self) -> JWKS:
        ...


def _ensure_bytes(key):
    if isinstance(key, str):
        key = key.encode("utf-8")
    return key


def _decode_value(val):
    decoded = base64.urlsafe_b64decode(_ensure_bytes(val) + b"==")
    return int.from_bytes(decoded, "big")


def _ensure_jwk_properties(jwk, *names):
    for name in names:
        if name not in jwk:
            raise ValueError(f"Expected a JWK defining a {name} property.")


def rsa_pem_from_jwk(jwk: JWK) -> bytes:
    _ensure_jwk_properties(jwk, "n", "e")
    return (
        RSAPublicNumbers(n=_decode_value(jwk["n"]), e=_decode_value(jwk["e"]))
        .public_key(default_backend())
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
