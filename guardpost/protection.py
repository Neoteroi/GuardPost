"""
This module provides classes to protect against brute-force attacks.
"""

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any, Callable, Optional, Sequence

from guardpost.errors import InvalidCredentialsError


class FailedAuthenticationAttempts:
    """
    A record class that stores the count of failed authentication attempts for an
    arbitrary key (e.g. client IP), and the time of the last failed attempt.
    """

    __slots__ = ("_key", "_counter", "_last_attempt_time")

    def __init__(self, key: str) -> None:
        self._key = key
        self._counter = 0
        self._last_attempt_time = datetime.now(tz=UTC)

    @property
    def key(self) -> str:
        """
        Returns the arbitrary key used to store the count of failed authentication
        attempts (e.g. client IP, or username and client IP).
        """
        return self._key

    @property
    def counter(self) -> int:
        """
        Returns the number of failed authentication attempts.
        """
        return self._counter

    @property
    def last_attempt_time(self) -> datetime:
        """
        Returns the UTC time of the last failed authentication attempt.
        """
        return self._last_attempt_time

    def increase_counter(self) -> int:
        """
        Increases the counter of failed authentication attempt by 1, and sets the
        last attempt time to UTC now.
        """
        self._counter += 1
        self._last_attempt_time = datetime.now(UTC)
        return self._counter

    def get_age(self) -> float:
        """
        Returns the number of seconds passed since the last authentication attempt.
        """
        return (datetime.now(UTC) - self._last_attempt_time).total_seconds()


class AuthenticationAttemptsStore(ABC):
    """
    Abstract base class for storing authentication attempts.

    Implementations of this class provide mechanisms to persist and manage failed
    authentication attempts, which can be used for rate limiting and brute-force
    protection. Subclasses must implement methods to retrieve, store, and clear
    failed attempts for a given key.
    """

    @abstractmethod
    async def get_failed_attempts(
        self, key: str
    ) -> Optional[FailedAuthenticationAttempts]: ...

    @abstractmethod
    async def set_failed_attempts(self, data: FailedAuthenticationAttempts) -> None: ...

    @abstractmethod
    async def clear_attempts(self, key: str) -> None: ...


class InMemoryAuthenticationAttemptsStore(AuthenticationAttemptsStore):
    """
    In-memory implementation of the AuthenticationAttemptsStore interface.

    This class stores authentication attempts in a dictionary that exists only for the
    lifetime of the application. All data is lost when the application restarts.

    This implementation is suitable for development, testing, or scenarios where
    persistence across application restarts is not required. For production environments
    it can be a 'good enough' default protection to store failed login attempts
    in-memory for each instance of the production app.
    """

    def __init__(self) -> None:
        super().__init__()
        self._attempts = {}

    async def get_failed_attempts(
        self, key: str
    ) -> Optional[FailedAuthenticationAttempts]:
        try:
            return self._attempts[key]
        except KeyError:
            return None

    async def clear_attempts(self, key: str) -> None:
        del self._attempts[key]

    async def set_failed_attempts(self, data: FailedAuthenticationAttempts) -> None:
        self._attempts[data.key] = data


class RateLimiter:
    """
    This class provides brute force protection by limiting the number of login attempts
    by arbitrary key (e.g. client ip address) within a specific time frame. After a
    certain number of attempts, the key can be temporarily blocked.
    """

    def __init__(
        self,
        threshold: int = 3,
        block_time: int = 300,
        store: Optional[AuthenticationAttemptsStore] = None,
        trusted_keys: Optional[Sequence[str]] = None,
        key_extractor: Optional[Callable[[Any], str]] = None,
    ) -> None:
        self._threshold = int(threshold)
        self._block_time = int(block_time)
        self._trusted_keys = set(trusted_keys) if trusted_keys else None
        self._store = store or InMemoryAuthenticationAttemptsStore()
        self._key_extractor = key_extractor

    def get_context_key(self, context: Any) -> str:
        if self._key_extractor:
            return self._key_extractor(context)
        return context.client_ip

    async def allow_authentication_attempt(self, context: Any) -> bool:
        """
        Determines if an authentication attempt should be allowed based on rate limiting
        rules. Returns True if the attempt should proceed, False if it should be
        blocked.
        """
        key = self.get_context_key(context)

        if self._trusted_keys and key in self._trusted_keys:
            return True

        failed_attempt = await self._store.get_failed_attempts(key)
        if failed_attempt is None:
            return True

        if failed_attempt.get_age() >= self._block_time:
            await self._store.clear_attempts(key)
            return True

        if failed_attempt.counter >= self._threshold:
            return False

        return True

    async def store_authentication_failure(self, error: InvalidCredentialsError):
        """
        Tracks information about a failed authentication attempt.
        """
        failed_attempt = await self._store.get_failed_attempts(error.key)
        if failed_attempt is None:
            failed_attempt = FailedAuthenticationAttempts(error.key)
        else:
            if failed_attempt.get_age() >= self._block_time:
                failed_attempt = FailedAuthenticationAttempts(error.key)
            else:
                failed_attempt.increase_counter()
        await self._store.set_failed_attempts(failed_attempt)
