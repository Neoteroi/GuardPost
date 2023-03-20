import time
from typing import Optional

from . import JWK, JWKS, KeysProvider


class CachingKeysProvider(KeysProvider):
    """
    Kind of KeysProvider that can cache the result of another KeysProvider.
    """

    def __init__(
        self, keys_provider: KeysProvider, cache_time: float, refresh_time: float = 120
    ) -> None:
        """
        Creates a new instance of CachingKeysProvider bound to a given KeysProvider,
        and caching its result up to an optional amount of seconds described by
        cache_time. Expiration is disabled if `cache_time` <= 0.
        JWKS are refreshed anyway if an unknown `kid` is encountered and the set was
        fetched more than `refresh_time` seconds ago.
        """
        super().__init__()

        if not keys_provider:
            raise TypeError("Missing KeysProvider")

        self._keys: Optional[JWKS] = None
        self._cache_time = cache_time
        self._refresh_time = refresh_time
        self._last_fetch_time: float = 0
        self._keys_provider = keys_provider

    @property
    def keys_provider(self) -> KeysProvider:
        return self._keys_provider

    async def _fetch_keys(self) -> JWKS:
        self._keys = await self._keys_provider.get_keys()
        self._last_fetch_time = time.time()
        return self._keys

    async def _refresh_keys(self) -> JWKS:
        new_set = await self._fetch_keys()
        if self._keys is None:  # pragma: no cover
            self._keys = new_set
        else:
            self._keys.update(new_set)
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

    async def get_key(self, kid: str) -> Optional[JWK]:
        """
        Tries to get a JWK by kid. If the JWK is not found and the last time the keys
        were fetched is older than `refresh_time` (default 120 seconds), it fetches
        again the JWKS from the source.
        """
        jwks = await self.get_keys()

        for jwk in jwks.keys.copy():
            if jwk.kid is not None and jwk.kid == kid:
                return jwk

        if (
            self._refresh_time > 0
            and time.time() - self._last_fetch_time >= self._refresh_time
        ):
            jwks = await self._refresh_keys()

            for jwk in jwks.keys.copy():
                if jwk.kid is not None and jwk.kid == kid:
                    return jwk

        return None
