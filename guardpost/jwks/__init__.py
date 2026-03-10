import base64
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Type

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    SECP384R1,
    SECP521R1,
    EllipticCurve,
    EllipticCurvePublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

from guardpost.errors import UnsupportedFeatureError


def _raise_if_missing(value: dict, *keys: str) -> None:
    for key in keys:
        if key not in value or not bool(value[key]):
            raise ValueError(f"Missing {key}")


_EC_CURVES: Dict[str, Type[EllipticCurve]] = {
    "P-256": SECP256R1,
    "P-384": SECP384R1,
    "P-521": SECP521R1,
}


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

    Supports RSA keys (kty="RSA") and EC keys (kty="EC") with curves
    P-256, P-384, and P-521.

    For more information: https://datatracker.ietf.org/doc/html/rfc7517
    """

    kty: KeyType
    pem: bytes
    kid: Optional[str] = None
    # RSA parameters
    n: Optional[str] = None
    e: Optional[str] = None
    # EC parameters
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None

    @classmethod
    def from_dict(cls, value) -> "JWK":
        key_type = KeyType.from_str(value.get("kty"))

        if key_type == KeyType.RSA:
            _raise_if_missing(value, "n", "e")
            return cls(
                kty=key_type,
                n=value["n"],
                e=value["e"],
                kid=value.get("kid"),
                pem=rsa_pem_from_n_and_e(value["n"], value["e"]),
            )

        if key_type == KeyType.EC:
            _raise_if_missing(value, "crv", "x", "y")
            return cls(
                kty=key_type,
                crv=value["crv"],
                x=value["x"],
                y=value["y"],
                kid=value.get("kid"),
                pem=ec_pem_from_x_y_crv(value["x"], value["y"], value["crv"]),
            )

        raise UnsupportedFeatureError(
            f"Unsupported key type: {key_type.value}. "
            "This library supports RSA and EC public keys."
        )


@dataclass
class JWKS:
    keys: List[JWK]

    def update(self, new_set: "JWKS"):
        self.keys = list({key.kid: key for key in self.keys + new_set.keys}.values())

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


def ec_pem_from_x_y_crv(x: str, y: str, crv: str) -> bytes:
    curve_cls = _EC_CURVES.get(crv)
    if curve_cls is None:
        raise ValueError(
            f"Unsupported EC curve: {crv!r}. "
            f"Supported curves: {', '.join(_EC_CURVES)}."
        )
    x_int = _decode_value(x)
    y_int = _decode_value(y)
    return (
        EllipticCurvePublicNumbers(x=x_int, y=y_int, curve=curve_cls())
        .public_key(default_backend())
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
