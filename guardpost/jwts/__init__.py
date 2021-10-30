import logging
from typing import Optional, Sequence

import jwt
from jwt.exceptions import InvalidIssuerError

from ..jwks import JWK, JWKS, rsa_pem_from_jwk
from ..jwks.openid import AuthorityKeysProvider


def get_logger():
    return logging.getLogger("auth-jwts")


class OAuthException(Exception):
    """Base class for exception risen when there is an issue related to OAuth."""


class InvalidAuthorizationToken(Exception):
    def __init__(self, details):
        super().__init__("Invalid authorization token: " + details)


def get_kid(token: str):
    """
    Extracts a kid (key id) from a JWT.
    The kid is necessary for signature verification.
    """
    headers = jwt.get_unverified_header(token)
    if not headers:
        raise InvalidAuthorizationToken("missing headers")
    try:
        return headers["kid"]
    except KeyError:
        raise InvalidAuthorizationToken("missing kid")


class JWTValidator:
    def __init__(
        self,
        *,
        authority: str,
        valid_issuers: Sequence[str],
        valid_audiences: Sequence[str],
        algorithms: Sequence[str] = ["RS256"],
    ) -> None:
        self._authority = authority
        self._valid_issuers = list(valid_issuers)
        self._valid_audiences = list(valid_audiences)
        self._algorithms = list(algorithms)
        self._keys_provider = AuthorityKeysProvider(authority)
        self._jwks: Optional[JWKS] = None
        self.logger = get_logger()

    async def get_jwks(self) -> JWKS:
        if self._jwks is not None:
            return self._jwks
        self._jwks = await self._keys_provider.get_keys()
        return self._jwks

    async def get_jwk(self, kid) -> JWK:
        jwks = await self.get_jwks()

        if "keys" not in jwks:
            raise OAuthException("Expected a JWKS structure defining a `keys` property")

        for jwk in jwks.get("keys", {}):
            if jwk.get("kid") == kid:
                return jwk
        raise InvalidAuthorizationToken("kid not recognized")

    async def get_public_key(self, token):
        return rsa_pem_from_jwk(await self.get_jwk(get_kid(token)))

    async def validate_jwt(self, access_token: str):
        """
        Validates the given JWT and returns its payload. This method throws exception
        if the JWT is not valid (i.e. its signature cannot be verified, for example
        because the JWT expired).
        """
        public_key = await self.get_public_key(access_token)

        for issuer in self._valid_issuers:
            try:
                return jwt.decode(
                    access_token,
                    public_key,  # type: ignore
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

        raise InvalidAuthorizationToken("Invalid access token.")
