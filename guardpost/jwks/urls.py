from guardpost.utils import get_running_loop, read_json_data

from . import JWKS, KeysProvider


def read_jwks_from_url(url: str) -> JWKS:
    jwks = read_json_data(url)
    return JWKS.from_dict(jwks)


async def read_jwks_from_url_async(url: str) -> JWKS:
    loop = get_running_loop()
    return await loop.run_in_executor(None, lambda: read_jwks_from_url(url))


class URLKeysProvider(KeysProvider):
    """
    Kind of KeysProvider that obtains JWKS from a given URL.
    """

    def __init__(self, url: str) -> None:
        """
        Creates an instance of URLKeysProvider bound to the given URL.
        """
        super().__init__()
        if not url:
            raise TypeError("Missing URL")
        self._url = url

    @property
    def url(self) -> str:
        return self._url

    async def get_keys(self) -> JWKS:
        return await read_jwks_from_url_async(self._url)
