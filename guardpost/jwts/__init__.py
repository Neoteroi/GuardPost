from typing import Any, Dict, Optional, Sequence, List, Union, Protocol

import jwt
from jwt.exceptions import InvalidIssuerError, InvalidTokenError

from ..jwks import JWK, JWKS, KeysProvider
from ..jwks.caching import CachingKeysProvider
from ..jwks.openid import AuthorityKeysProvider
from ..jwks.urls import URLKeysProvider
from ..utils import get_logger


class OAuthException(Exception):
    """Base class for exception risen when there is an issue related to OAuth."""


class InvalidAccessToken(Exception):
    def __init__(self, details=""):
        if details:
            message = "Invalid access token: " + details
        else:
            message = "Invalid access token."
        super().__init__(message)


def get_kid(token: str) -> Optional[str]:
    """
    Extracts a kid (key id) from a JWT.
    """
    headers = jwt.get_unverified_header(token)
    if not headers:  # pragma: no cover
        raise InvalidAccessToken("missing headers")
    return headers.get("kid")


class JWTValidatorProtocol(Protocol):
    """Protocol defining the interface for JWT validators"""

    async def validate_jwt(self, access_token: str) -> Dict[str, Any]: ...


class BaseJWTValidator:
    """Base class for JWT validators with common functionality."""

    def __init__(
        self,
        *,
        valid_issuers: Sequence[str],
        valid_audiences: Sequence[str],
        algorithms: Sequence[str],
    ) -> None:
        self._valid_issuers = list(valid_issuers)
        self._valid_audiences = list(valid_audiences)
        self._algorithms = list(algorithms)
        self.logger = get_logger()


class AsymmetricJWTValidator(BaseJWTValidator):
    """
    A JWTValidator that can validate JWTs signed using asymmetric encryption.
    """

    def __init__(
        self,
        *,
        valid_issuers: Sequence[str],
        valid_audiences: Sequence[str],
        authority: Optional[str] = None,
        algorithms: Sequence[str] = ["RS256"],
        require_kid: bool = True,
        keys_provider: Optional[KeysProvider] = None,
        keys_url: Optional[str] = None,
        cache_time: float = 10800,
        refresh_time: float = 120,
    ) -> None:
        """
        Creates a new instance of AsymmetricJWTValidator. This class supports validating
        access tokens signed using asymmetric keys and handling JWKs of RSA type.

        Parameters
        ----------
        valid_issuers : Sequence[str]
            Sequence of acceptable issuers (iss).
        valid_audiences : Sequence[str]
            Sequence of acceptable audiences (aud).
        authority : Optional[str], optional
            If provided, keys are obtained from a standard well-known endpoint.
            This parameter is ignored if `keys_provider` is given.
        algorithms : Sequence[str], optional
            Sequence of acceptable algorithms, by default ["RS256"].
        require_kid : bool, optional
            According to the specification, a key id is optional in JWK. However,
            this parameter lets control whether access tokens missing `kid` in their
            headers should be handled or rejected. By default True, thus only JWTs
            having `kid` header are accepted.
        keys_provider : Optional[KeysProvider], optional
            If provided, the exact `KeysProvider` to be used when fetching keys.
            By default None
        keys_url : Optional[str], optional
            If provided, keys are obtained from the given URL through HTTP GET.
            This parameter is ignored if `keys_provider` is given.
        cache_time : float
            JWKS are cached in memory and stored for the given amount in seconds.
            By default 10800 (3 hours). Regardless of this parameter, JWKS are refreshed
            automatically if an unknown kid is met and JWKS were last fetched more than
            `refresh_time` earlier (in seconds).
        refresh_time : float
            JWKS are refreshed automatically if an unknown `kid` is encountered, and
            JWKS were last fetched more than `refresh_time` seconds ago (by default
            120 seconds)
        """
        super().__init__(
            valid_issuers=valid_issuers,
            valid_audiences=valid_audiences,
            algorithms=algorithms,
        )

        if keys_provider:
            pass
        elif authority:
            keys_provider = AuthorityKeysProvider(authority)
        elif keys_url:
            keys_provider = URLKeysProvider(keys_url)

        if keys_provider is None:
            raise TypeError(
                "Missing `keys_provider`, either provide a `url` source, "
                "`authority`, or `keys_provider`."
            )

        self._keys_provider = CachingKeysProvider(
            keys_provider, cache_time, refresh_time
        )
        self.require_kid = require_kid

    async def get_jwks(self) -> JWKS:
        return await self._keys_provider.get_keys()

    async def get_jwk(self, kid: str) -> JWK:
        key = await self._keys_provider.get_key(kid)

        if key is None:
            raise InvalidAccessToken("kid not recognized")
        return key

    def _validate_jwt_by_key(
        self, access_token: str, jwk: JWK
    ) -> Optional[Dict[str, Any]]:
        for issuer in self._valid_issuers:
            try:
                return jwt.decode(
                    access_token,
                    jwk.pem,  # type: ignore
                    verify=True,
                    algorithms=self._algorithms,
                    audience=self._valid_audiences,
                    issuer=issuer,
                )
            except InvalidIssuerError:
                # pass, because the application might support more than one issuer;
                # note that token verification might fail for several other reasons
                # that are not catched (e.g. expired signature)
                pass
            except InvalidTokenError as exc:
                self.logger.debug("Invalid access token: ", exc_info=exc)
                return None
        return None

    async def validate_jwt(self, access_token: str) -> Dict[str, Any]:
        """
        Validates the given JWT and returns its payload. This method throws exception
        if the JWT is not valid (i.e. its signature cannot be verified, for example
        because the JWT expired).
        """
        kid = get_kid(access_token)
        if kid is None and self.require_kid:
            # A key id is optional according to the specification,
            # but here we expect a kid by default.
            # Disabling require_kid makes this method less efficient.
            raise InvalidAccessToken("Missing key id (kid).")

        if kid is None:
            # Unoptimal scenario: the identity provider does not handle key ids,
            # thus if more than one JWK is configured in the JWKS, we need to cycle
            # and attempt each of them
            jwks = await self.get_jwks()

            for jwk in jwks.keys:
                data = self._validate_jwt_by_key(access_token, jwk)
                if data is not None:
                    return data
        else:
            # Preferred scenario: the identity provider handles key ids,
            # thus we can validate an access token using an exact key
            jwk = await self.get_jwk(kid)
            data = self._validate_jwt_by_key(access_token, jwk)
            if data is not None:
                return data

        raise InvalidAccessToken()


class SymmetricJWTValidator(BaseJWTValidator):
    def __init__(
        self,
        *,
        valid_issuers: Sequence[str],
        valid_audiences: Sequence[str],
        secret_key: Union[str, bytes],
        algorithms: Sequence[str] = ["HS256"],
    ) -> None:
        """
        Creates a new instance of SymmetricJWTValidator. This class supports validating
        access tokens signed using symmetric keys (HMAC).

        Parameters
        ----------
        valid_issuers : Sequence[str]
            Sequence of acceptable issuers (iss).
        valid_audiences : Sequence[str]
            Sequence of acceptable audiences (aud).
        secret_key : Union[str, bytes]
            The secret key used for symmetric validation.
        algorithms : Sequence[str], optional
            Sequence of acceptable algorithms, by default ["HS256"].
            Supported algorithms: HS256, HS384, HS512
        """
        super().__init__(
            valid_issuers=valid_issuers,
            valid_audiences=valid_audiences,
            algorithms=algorithms,
        )

        supported_algorithms = ["HS256", "HS384", "HS512"]
        for algorithm in algorithms:
            if algorithm not in supported_algorithms:
                raise ValueError(
                    f"Algorithm '{algorithm}' is not supported for symmetric validation. "
                    f"Use one of: {', '.join(supported_algorithms)}"
                )

        self._secret_key = secret_key

    async def validate_jwt(self, access_token: str) -> Dict[str, Any]:
        """
        Validates the given JWT using symmetric key and returns its payload.
        This method throws exception if the JWT is not valid.
        """
        for issuer in self._valid_issuers:
            try:
                return jwt.decode(
                    access_token,
                    self._secret_key,
                    verify=True,
                    algorithms=self._algorithms,
                    audience=self._valid_audiences,
                    issuer=issuer,
                )
            except InvalidIssuerError:
                # Try the next issuer
                pass
            except InvalidTokenError as exc:
                self.logger.debug("Invalid access token: ", exc_info=exc)

        # If we've tried all issuers and none worked
        raise InvalidAccessToken()


class CompositeJWTValidator(BaseJWTValidator):
    def __init__(self, validators: List[JWTValidatorProtocol]) -> None:
        """
        Creates a composite validator that tries multiple validation strategies.
        Useful when you need to support both symmetric and asymmetric validation.

        Parameters
        ----------
        validators : List[JWTValidatorProtocol]
            List of validators to try in sequence
        """
        self._validators = validators
        self.logger = get_logger()

    async def validate_jwt(self, access_token: str) -> Dict[str, Any]:
        """
        Attempts to validate the JWT using each validator in sequence.
        Returns the first successful validation result or raises InvalidAccessToken
        if all validators fail.
        """
        exceptions = []

        for validator in self._validators:
            try:
                return await validator.validate_jwt(access_token)
            except InvalidAccessToken as exc:
                exceptions.append(exc)
                # Continue to the next validator

        # If we get here, all validators failed
        if exceptions:
            self.logger.debug(f"All validators failed: {exceptions}")
        raise InvalidAccessToken(
            "Token validation failed with all configured validators"
        )


# For backward compatibility, keep the original name
JWTValidator = AsymmetricJWTValidator
