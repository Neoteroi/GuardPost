from guardpost.utils import get_running_loop, read_json_data

from . import JWKS, KeysProvider


def _read_openid_configuration(authority: str):
    return read_json_data(authority.rstrip("/") + "/.well-known/openid-configuration")


def read_jwks_from_authority(authority: str) -> JWKS:
    openid_config = _read_openid_configuration(authority)

    if "jwks_uri" not in openid_config:  # pragma: no cover
        raise ValueError("Expected a `jwks_uri` property in the OpenID Configuration")

    jwks = read_json_data(openid_config["jwks_uri"])
    return JWKS.from_dict(jwks)


async def read_jwks_from_authority_async(authority: str) -> JWKS:
    loop = get_running_loop()
    return await loop.run_in_executor(None, lambda: read_jwks_from_authority(authority))


class AuthorityKeysProvider(KeysProvider):
    """
    Kind of KeysProvider that uses the /.well-known/openid-configuration
    discovery endpoint to obtain the `jwks_uri` and the JWKS.
    """

    def __init__(self, authority: str) -> None:
        """
        Creates an instance of AuthorityKeysProvider bound to the given authority.
        """
        super().__init__()
        if not authority:
            raise TypeError("Missing authority")
        self._authority = authority

    @property
    def authority(self) -> str:
        return self._authority

    async def get_keys(self) -> JWKS:
        return await read_jwks_from_authority_async(self._authority)
