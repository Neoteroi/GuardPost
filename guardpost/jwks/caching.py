import time
from typing import Optional

from . import JWKS, KeysProvider


class CachingKeysProvider(KeysProvider):
    """
    Kind of KeysProvider that can cache the result of another KeysProvider.
    """

    def __init__(self, keys_provider: KeysProvider, cache_time: float) -> None:
        """
        Creates a new instance of CachingKeysProvider bound to a given KeysProvider,
        and caching its result up to an optional amount of seconds described by
        cache_time. Expiration is disabled if `cache_time` <= 0.
        """
        super().__init__()

        if not keys_provider:
            raise TypeError("Missing KeysProvider")

        self._keys: Optional[JWKS] = None
        self._cache_time = cache_time
        self._last_fetch_time: float = 0
        self._keys_provider = keys_provider

    @property
    def keys_provider(self) -> KeysProvider:
        return self._keys_provider

    async def _fetch_keys(self) -> JWKS:
        self._keys = await self._keys_provider.get_keys()
        self._last_fetch_time = time.time()
        return self._keys

    async def get_keys(self) -> JWKS:
        if self._keys is not None:
            if self._cache_time > 0 and (
                time.time() - self._last_fetch_time >= self._cache_time
            ):
                pass
            else:
                return self._keys
        return await self._fetch_keys()
