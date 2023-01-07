import pytest

from guardpost.errors import UnsupportedFeatureError
from guardpost.jwks import JWK, JWKS, KeyType


def test_keytype_from_str():
    assert KeyType.from_str("EC") is KeyType.EC
    assert KeyType.from_str("oct") is KeyType.OCT
    assert KeyType.from_str("RSA") is KeyType.RSA
    assert KeyType.from_str("OKP") is KeyType.OKP

    with pytest.raises(ValueError):
        KeyType.from_str("xx")

    with pytest.raises(ValueError):
        KeyType.from_str("")


def test_jwks_raises_for_missing_keys():
    with pytest.raises(ValueError):
        JWKS.from_dict({})


def test_jwk_raises_for_unsupported_type():
    with pytest.raises(UnsupportedFeatureError):
        JWK.from_dict({"kty": "oct"})

    with pytest.raises(ValueError):
        JWK.from_dict({"kty": "RSA"})
