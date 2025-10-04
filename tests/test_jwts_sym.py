import time
from typing import Any, Dict

import jwt
import pytest

from guardpost.jwts import InvalidAccessToken, SymmetricJWTValidator


def create_symmetric_token(
    payload: Dict[str, Any], secret: str, algorithm: str = "HS256"
) -> str:
    """Helper function to create symmetric JWT tokens for testing."""
    return jwt.encode(payload, secret, algorithm=algorithm)


def create_expired_token(
    payload: Dict[str, Any], secret: str, algorithm: str = "HS256"
) -> str:
    """Helper function to create expired JWT tokens for testing."""
    # Create a token that expired 1 hour ago
    expired_payload = payload.copy()
    expired_payload["exp"] = int(time.time()) - 3600
    return jwt.encode(expired_payload, secret, algorithm=algorithm)


class TestSymmetricJWTValidator:
    """Test suite for SymmetricJWTValidator"""

    def test_validator_creation_with_default_algorithm(self):
        """Test creating validator with default HS256 algorithm"""
        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key="test-secret",
        )
        assert validator._algorithms == ["HS256"]
        assert validator._secret_key == "test-secret"

    def test_validator_creation_with_custom_algorithms(self):
        """Test creating validator with custom algorithms"""
        algorithms = ["HS256", "HS384", "HS512"]
        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key="test-secret",
            algorithms=algorithms,
        )
        assert validator._algorithms == algorithms

    def test_validator_creation_with_bytes_secret(self):
        """Test creating validator with bytes secret key"""
        secret = b"test-secret-bytes"
        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
        )
        assert validator._secret_key == secret

    def test_validator_rejects_unsupported_algorithm(self):
        """Test that validator rejects unsupported algorithms"""
        with pytest.raises(ValueError, match="Algorithm 'RS256' is not supported"):
            SymmetricJWTValidator(
                valid_issuers=["test-issuer"],
                valid_audiences=["test-audience"],
                secret_key="test-secret",
                algorithms=["RS256"],
            )

    def test_validator_rejects_mixed_unsupported_algorithms(self):
        """Test that validator rejects when any algorithm is unsupported"""
        with pytest.raises(ValueError, match="Algorithm 'ES256' is not supported"):
            SymmetricJWTValidator(
                valid_issuers=["test-issuer"],
                valid_audiences=["test-audience"],
                secret_key="test-secret",
                algorithms=["HS256", "ES256"],
            )

    @pytest.mark.asyncio
    async def test_validate_valid_hs256_token(self):
        """Test validating a valid HS256 token"""
        secret = "test-secret-key"
        payload = {"iss": "test-issuer", "aud": "test-audience", "sub": "user123"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
        )

        token = create_symmetric_token(payload, secret, "HS256")
        result = await validator.validate_jwt(token)

        assert result["iss"] == "test-issuer"
        assert result["aud"] == "test-audience"
        assert result["sub"] == "user123"

    @pytest.mark.asyncio
    async def test_validate_valid_hs384_token(self):
        """Test validating a valid HS384 token"""
        secret = "test-secret-key-for-hs384"
        payload = {"iss": "test-issuer", "aud": "test-audience", "sub": "user123"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
            algorithms=["HS384"],
        )

        token = create_symmetric_token(payload, secret, "HS384")
        result = await validator.validate_jwt(token)

        assert result["iss"] == "test-issuer"
        assert result["aud"] == "test-audience"

    @pytest.mark.asyncio
    async def test_validate_valid_hs512_token(self):
        """Test validating a valid HS512 token"""
        secret = "test-secret-key-for-hs512-algorithm"
        payload = {"iss": "test-issuer", "aud": "test-audience", "sub": "user123"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
            algorithms=["HS512"],
        )

        token = create_symmetric_token(payload, secret, "HS512")
        result = await validator.validate_jwt(token)

        assert result["iss"] == "test-issuer"
        assert result["aud"] == "test-audience"

    @pytest.mark.asyncio
    async def test_validate_multiple_algorithms(self):
        """Test validator with multiple algorithms accepts all of them"""
        secret = "test-secret-key"
        payload = {"iss": "test-issuer", "aud": "test-audience"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
            algorithms=["HS256", "HS384", "HS512"],
        )

        # Test each algorithm
        for algorithm in ["HS256", "HS384", "HS512"]:
            token = create_symmetric_token(payload, secret, algorithm)
            result = await validator.validate_jwt(token)
            assert result["iss"] == "test-issuer"
            assert result["aud"] == "test-audience"

    @pytest.mark.asyncio
    async def test_validate_multiple_issuers(self):
        """Test validator with multiple valid issuers"""
        secret = "test-secret-key"
        validator = SymmetricJWTValidator(
            valid_issuers=["issuer1", "issuer2", "issuer3"],
            valid_audiences=["test-audience"],
            secret_key=secret,
        )

        # Test each issuer
        for issuer in ["issuer1", "issuer2", "issuer3"]:
            payload = {"iss": issuer, "aud": "test-audience"}
            token = create_symmetric_token(payload, secret)
            result = await validator.validate_jwt(token)
            assert result["iss"] == issuer

    @pytest.mark.asyncio
    async def test_validate_multiple_audiences(self):
        """Test validator with multiple valid audiences"""
        secret = "test-secret-key"
        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["aud1", "aud2", "aud3"],
            secret_key=secret,
        )

        # Test each audience
        for audience in ["aud1", "aud2", "aud3"]:
            payload = {"iss": "test-issuer", "aud": audience}
            token = create_symmetric_token(payload, secret)
            result = await validator.validate_jwt(token)
            assert result["aud"] == audience

    @pytest.mark.asyncio
    async def test_validate_fails_wrong_secret(self):
        """Test validation fails with wrong secret key"""
        secret = "correct-secret"
        wrong_secret = "wrong-secret"
        payload = {"iss": "test-issuer", "aud": "test-audience"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=wrong_secret,
        )

        token = create_symmetric_token(payload, secret)

        with pytest.raises(InvalidAccessToken):
            await validator.validate_jwt(token)

    @pytest.mark.asyncio
    async def test_validate_fails_invalid_issuer(self):
        """Test validation fails with invalid issuer"""
        secret = "test-secret"
        payload = {"iss": "invalid-issuer", "aud": "test-audience"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
        )

        token = create_symmetric_token(payload, secret)

        with pytest.raises(InvalidAccessToken):
            await validator.validate_jwt(token)

    @pytest.mark.asyncio
    async def test_validate_fails_invalid_audience(self):
        """Test validation fails with invalid audience"""
        secret = "test-secret"
        payload = {"iss": "test-issuer", "aud": "invalid-audience"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
        )

        token = create_symmetric_token(payload, secret)

        with pytest.raises(InvalidAccessToken):
            await validator.validate_jwt(token)

    @pytest.mark.asyncio
    async def test_validate_fails_expired_token(self):
        """Test validation fails with expired token"""
        secret = "test-secret"
        payload = {"iss": "test-issuer", "aud": "test-audience"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
        )

        token = create_expired_token(payload, secret)

        with pytest.raises(InvalidAccessToken):
            await validator.validate_jwt(token)

    @pytest.mark.asyncio
    async def test_validate_fails_malformed_token(self):
        """Test validation fails with malformed token"""
        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key="test-secret",
        )

        malformed_token = "not.a.valid.jwt.token"

        with pytest.raises(InvalidAccessToken):
            await validator.validate_jwt(malformed_token)

    @pytest.mark.asyncio
    async def test_validate_fails_empty_token(self):
        """Test validation fails with empty token"""
        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key="test-secret",
        )

        with pytest.raises(InvalidAccessToken):
            await validator.validate_jwt("")

    @pytest.mark.asyncio
    async def test_validate_with_bytes_secret_key(self):
        """Test validation works with bytes secret key"""
        secret = b"test-secret-bytes"
        payload = {"iss": "test-issuer", "aud": "test-audience"}

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
        )

        token = jwt.encode(payload, secret, algorithm="HS256")
        result = await validator.validate_jwt(token)

        assert result["iss"] == "test-issuer"
        assert result["aud"] == "test-audience"

    @pytest.mark.asyncio
    async def test_validate_token_with_additional_claims(self):
        """Test validation preserves additional claims in token"""
        secret = "test-secret"
        payload = {
            "iss": "test-issuer",
            "aud": "test-audience",
            "sub": "user123",
            "name": "John Doe",
            "roles": ["admin", "user"],
            "custom_claim": "custom_value",
        }

        validator = SymmetricJWTValidator(
            valid_issuers=["test-issuer"],
            valid_audiences=["test-audience"],
            secret_key=secret,
        )

        token = create_symmetric_token(payload, secret)
        result = await validator.validate_jwt(token)

        assert result["sub"] == "user123"
        assert result["name"] == "John Doe"
        assert result["roles"] == ["admin", "user"]
        assert result["custom_claim"] == "custom_value"
