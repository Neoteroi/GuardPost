import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from guardpost.errors import UnsupportedFeatureError


def _raise_if_missing(value: dict, *keys: str) -> None:
    for key in keys:
        if key not in value or not bool(value[key]):
            raise ValueError(f"Missing {key}")


class KeyType(Enum):
    EC = "EC"
    RSA = "RSA"
    OCT = "oct"
    OKP = "OKP"

    @classmethod
    def from_str(cls, value: str) -> "KeyType":
        if not value:
            raise ValueError("Missing key type (kty)")
        try:
            return cls[value.upper()]
        except KeyError:
            raise ValueError(f"Invalid JWT kty parameter: {value}")


@dataclass
class JWK:
    """
    This class provides an interface to a JSON Web Key.
    A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
    structure that represents a cryptographic key.

    For more information: https://datatracker.ietf.org/doc/html/rfc7517
    """

    kty: KeyType
    n: str
    e: str
    pem: bytes
    kid: Optional[str] = None

    @classmethod
    def from_dict(cls, value) -> "JWK":
        key_type = KeyType.from_str(value.get("kty"))

        if key_type != KeyType.RSA:
            raise UnsupportedFeatureError("This library supports only RSA public keys.")

        _raise_if_missing(value, "n", "e")
        return cls(
            kty=key_type,
            n=value["n"],
            e=value["e"],
            kid=value.get("kid"),
            pem=rsa_pem_from_n_and_e(value["n"], value["e"]),
        )


@dataclass
class JWKS:
    keys: List[JWK]

    @classmethod
    def from_dict(cls, value) -> "JWKS":
        if "keys" not in value:
            raise ValueError("Invalid JWKS structure, missing `keys` property.")
        return cls(keys=[JWK.from_dict(item) for item in value["keys"]])


class KeysProvider(ABC):
    """
    Base for classes that can provide a JWKS from a source.
    """

    @abstractmethod
    async def get_keys(self) -> JWKS:
        """Returns a JWKS."""


class InMemoryKeysProvider(KeysProvider):
    """
    Type of keys provider that stores keys in memory.
    """

    def __init__(self, keys: JWKS) -> None:
        """
        Creates a new instance of InMemoryKeysProvider bound to the given JWKS.

        Parameters
        ----------
        keys : JWKS
            Exact keys handled by this instance.
        """
        super().__init__()
        self._keys = keys

    async def get_keys(self) -> JWKS:
        return self._keys


def _ensure_bytes(key):
    if isinstance(key, str):
        key = key.encode("utf-8")
    return key


def _decode_value(val):
    decoded = base64.urlsafe_b64decode(_ensure_bytes(val) + b"==")
    return int.from_bytes(decoded, "big")


def rsa_pem_from_n_and_e(n: str, e: str) -> bytes:
    return (
        RSAPublicNumbers(n=_decode_value(n), e=_decode_value(e))
        .public_key(default_backend())
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
