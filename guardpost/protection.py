"""
This module provides classes to protect against brute-force attacks.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Optional, Sequence

from guardpost.errors import InvalidCredentialsError


class FailedAttempts:

    __slots__ = ("_key", "_counter", "_last_attempt_time")

    def __init__(self, key: str) -> None:
        self._key = key
        self._counter = 0
        self._last_attempt_time = datetime.now(tz=UTC)

    @property
    def key(self) -> str:
        return self._key

    @property
    def counter(self) -> int:
        return self._counter

    @property
    def last_attempt_time(self) -> datetime:
        return self._last_attempt_time

    def increase_counter(self) -> int:
        self._counter += 1
        self._last_attempt_time = datetime.now(UTC)
        return self._counter

    def get_age(self) -> float:
        """
        Returns the number of seconds passed since the last authentication attempt.
        """
        return (datetime.now(UTC) - self._last_attempt_time).total_seconds()

    def __iadd__(self):
        self._counter += 1
        self._last_attempt_time = datetime.now(tz=UTC)


class AuthenticationAttemptsStore(ABC):

    @abstractmethod
    async def get_failed_attempts(self, key: str) -> Optional[FailedAttempts]: ...

    @abstractmethod
    async def set_failed_attempts(self, data: FailedAttempts) -> None: ...

    @abstractmethod
    async def clear_attempts(self, key: str) -> None: ...


class InMemoryAuthenticationAttemptsStore(AuthenticationAttemptsStore):

    def __init__(self) -> None:
        super().__init__()
        self._attempts = {}

    async def get_failed_attempts(self, client_ip: str) -> Optional[FailedAttempts]:
        try:
            return self._attempts[client_ip]
        except KeyError:
            return None

    async def clear_attempts(self, key: str) -> None:
        del self._attempts[key]

    async def set_failed_attempts(self, data: FailedAttempts) -> None:
        self._attempts[data.key] = data


class RateLimiter:
    """
    This class provides brute force protection by limiting the number of login attempts
    from a single IP address within a specific time frame. After a certain number of
    attempts, the IP address can be temporarily blocked.
    """

    def __init__(
        self,
        threshold: int = 3,
        block_time: int = 300,
        store: Optional[AuthenticationAttemptsStore] = None,
        trusted_ips: Optional[Sequence[str]] = None,
    ) -> None:
        self._threshold = int(threshold)
        self._block_time = int(block_time)
        self._trusted_ips = set(trusted_ips) if trusted_ips else None
        self._store = store or InMemoryAuthenticationAttemptsStore()

    async def is_valid_context(self, client_ip: str) -> bool:
        """
        Verifies if the given context should be rate limited.
        """
        if self._trusted_ips and client_ip in self._trusted_ips:
            return True

        failed_attempt = await self._store.get_failed_attempts(client_ip)
        if failed_attempt is None:
            return True

        if failed_attempt.get_age() >= self._block_time:
            await self._store.clear_attempts(client_ip)
            return True

        if failed_attempt.counter >= self._threshold:
            return False

        return True

    async def store_failure(self, error: InvalidCredentialsError):
        failed_attempt = await self._store.get_failed_attempts(error.key)
        if failed_attempt is None:
            failed_attempt = FailedAttempts(error.key)
        else:
            if failed_attempt.get_age() >= self._block_time:
                failed_attempt = FailedAttempts(error.key)
            else:
                failed_attempt.increase_counter()
        await self._store.set_failed_attempts(failed_attempt)
