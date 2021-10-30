import asyncio
import json
import urllib.request

from ..errors import FailedRequestError
from . import JWKS, KeysProvider


def _read_json_data(url: str):
    with urllib.request.urlopen(url) as response:
        if response.status != 200:
            raise FailedRequestError(response)

        return json.loads(response.read())


def _read_openid_configuration(authority: str):
    return _read_json_data(authority.rstrip("/") + "/.well-known/openid-configuration")


def read_jwks_from_authority(authority: str) -> JWKS:
    openid_config = _read_openid_configuration(authority)

    if "jwks_uri" not in openid_config:
        raise ValueError("Expected a `jwks_uri` property in the OpenID Configuration")

    return _read_json_data(openid_config["jwks_uri"])


async def read_jwks_from_authority_async(authority: str) -> JWKS:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: read_jwks_from_authority(authority))


class AuthorityKeysProvider(KeysProvider):
    """
    This kind of KeysProvider uses the /.well-known/openid-configuration
    discovery endpoint to obtain the `jwks_uri` and the JWKS.
    """

    def __init__(self, authority: str) -> None:
        """
        Creates an instance of AuthorityKeysProvider bound to the given authority.
        """
        self._authority = authority

    @property
    def authority(self) -> str:
        return self._authority

    async def get_keys(self) -> JWKS:
        return await read_jwks_from_authority_async(self._authority)
