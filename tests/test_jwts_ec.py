"""
Tests for JWT validation using EC keys (ES256, ES384, ES512).
"""

import json
import os
from typing import Any, Dict

import jwt
import pytest

from guardpost.jwks import JWKS, InMemoryKeysProvider
from guardpost.jwts import AsymmetricJWTValidator, InvalidAccessToken


def _get_ec_jwks_dict():
    path = os.path.join(os.path.dirname(__file__), "res", "ec_jwks.json")
    with open(path, encoding="utf8") as f:
        return json.load(f)


def _get_file_path(file_name: str) -> str:
    return os.path.join(os.path.dirname(__file__), "res", file_name)


def get_ec_access_token(
    kid: str,
    payload: Dict[str, Any],
    algorithm: str,
    include_headers: bool = True,
    fake_kid: str = "",
) -> str:
    with open(_get_file_path(f"{kid}.pem"), "r") as key_file:
        private_key = key_file.read()
    return jwt.encode(
        payload,
        private_key,
        algorithm=algorithm,
        headers={"kid": fake_kid or kid} if include_headers else None,
    )


@pytest.fixture()
def ec_keys_provider() -> InMemoryKeysProvider:
    return InMemoryKeysProvider(JWKS.from_dict(_get_ec_jwks_dict()))


@pytest.mark.asyncio
async def test_ec_validator_validates_es256(ec_keys_provider):
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES256"],
    )
    payload = {"aud": "a", "iss": "b"}
    token = get_ec_access_token("ec256", payload, "ES256")
    result = await validator.validate_jwt(token)
    assert result == payload


@pytest.mark.asyncio
async def test_ec_validator_validates_es384(ec_keys_provider):
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES384"],
    )
    payload = {"aud": "a", "iss": "b"}
    token = get_ec_access_token("ec384", payload, "ES384")
    result = await validator.validate_jwt(token)
    assert result == payload


@pytest.mark.asyncio
async def test_ec_validator_validates_es512(ec_keys_provider):
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES512"],
    )
    payload = {"aud": "a", "iss": "b"}
    token = get_ec_access_token("ec521", payload, "ES512")
    result = await validator.validate_jwt(token)
    assert result == payload


@pytest.mark.asyncio
async def test_ec_validator_supports_multiple_algorithms(ec_keys_provider):
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES256", "ES384", "ES512"],
    )
    payload = {"aud": "a", "iss": "b"}
    for kid, alg in [("ec256", "ES256"), ("ec384", "ES384"), ("ec521", "ES512")]:
        token = get_ec_access_token(kid, payload, alg)
        result = await validator.validate_jwt(token)
        assert result == payload


@pytest.mark.asyncio
async def test_ec_validator_blocks_wrong_key(ec_keys_provider):
    """A token signed with ec384 key should not validate against ec256's public key."""
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES256", "ES384", "ES512"],
    )
    payload = {"aud": "a", "iss": "b"}
    # Sign with ec384 key but claim kid=ec256
    forged_token = get_ec_access_token("ec384", payload, "ES384", fake_kid="ec256")
    with pytest.raises(InvalidAccessToken):
        await validator.validate_jwt(forged_token)


@pytest.mark.asyncio
async def test_ec_validator_raises_for_invalid_issuer(ec_keys_provider):
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES256"],
    )
    payload = {"aud": "a", "iss": "WRONG"}
    token = get_ec_access_token("ec256", payload, "ES256")
    with pytest.raises(InvalidAccessToken):
        await validator.validate_jwt(token)


@pytest.mark.asyncio
async def test_ec_validator_raises_for_invalid_audience(ec_keys_provider):
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES256"],
    )
    payload = {"aud": "WRONG", "iss": "b"}
    token = get_ec_access_token("ec256", payload, "ES256")
    with pytest.raises(InvalidAccessToken):
        await validator.validate_jwt(token)


@pytest.mark.asyncio
async def test_ec_validator_raises_for_missing_kid(ec_keys_provider):
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES256"],
    )
    payload = {"aud": "a", "iss": "b"}
    token = get_ec_access_token("ec256", payload, "ES256", include_headers=False)
    with pytest.raises(InvalidAccessToken):
        await validator.validate_jwt(token)


@pytest.mark.asyncio
async def test_ec_validator_supports_no_kid_by_configuration(ec_keys_provider):
    validator = AsymmetricJWTValidator(
        valid_audiences=["a"],
        valid_issuers=["b"],
        keys_provider=ec_keys_provider,
        algorithms=["ES256", "ES384", "ES512"],
        require_kid=False,
    )
    payload = {"aud": "a", "iss": "b"}
    token = get_ec_access_token("ec256", payload, "ES256", include_headers=False)
    result = await validator.validate_jwt(token)
    assert result == payload
