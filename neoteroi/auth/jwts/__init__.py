from typing import Any, Dict, Optional, Sequence

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


class JWTValidator:
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
        cache_time: float = 10800
    ) -> None:
        """
        Creates a new instance of JWTValidator. This class only supports validating
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
        cache_time : float, optional
            If >= 0, JWKS are cached in memory and stored for the given amount in
            seconds. By default 10800 (3 hours).
        """
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

        if cache_time:
            keys_provider = CachingKeysProvider(keys_provider, cache_time)

        self._valid_issuers = list(valid_issuers)
        self._valid_audiences = list(valid_audiences)
        self._algorithms = list(algorithms)
        self._keys_provider: KeysProvider = keys_provider
        self.require_kid = require_kid
        self.logger = get_logger()

    async def get_jwks(self) -> JWKS:
        return await self._keys_provider.get_keys()

    async def get_jwk(self, kid: str) -> JWK:
        jwks = await self.get_jwks()

        for jwk in jwks.keys:
            if jwk.kid is not None and jwk.kid == kid:
                return jwk
        raise InvalidAccessToken("kid not recognized")

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
