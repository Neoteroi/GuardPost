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
        self._counter = 1  # must start from the first attempt
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
    ) -> Optional[FailedAuthenticationAttempts]:
        """
        Returns the record tracking the number of failed authentication attempts for a
        given context key (e.g. client IP), or none if no failed attempt exists for the
        given key.
        """

    @abstractmethod
    async def set_failed_attempts(self, data: FailedAuthenticationAttempts) -> None:
        """
        Stores or updates a record describing the number of failed authentication
        attempts for a given context key (e.g. client IP).
        """

    @abstractmethod
    async def clear_attempts(self, key: str) -> None:
        """
        Deletes the failed authentication attempts record for the given context key.
        """


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
        key_getter: Optional[Callable[[Any], str]] = None,
        threshold: int = 20,
        block_time: int = 60,
        store: Optional[AuthenticationAttemptsStore] = None,
        trusted_keys: Optional[Sequence[str]] = None,
    ) -> None:
        """
        Initialize a RateLimiter instance for brute-force protection.

        Args:
            key_getter: Optional callable that extracts a unique key from the
                authentication context (e.g., client IP address, username).
                If None, brute-force protection is disabled and a deprecation
                warning is issued.
            threshold: Maximum number of failed authentication attempts allowed
                before blocking. Must be a positive integer. Defaults to 20.
            block_time: Duration in seconds to block further attempts after
                threshold is exceeded. Must be a positive integer. Defaults to 60.
            store: Storage backend for persisting authentication attempts.
                If None, uses InMemoryAuthenticationAttemptsStore by default.
            trusted_keys: Optional sequence of keys that bypass rate limiting
                (e.g., trusted IP addresses). These keys are never blocked
                regardless of failed attempt count.

        Note:
            Setting key_getter to None disables brute-force protection entirely.
            This behavior is deprecated and will be removed in a future version.
            It is discouraged in production environments.
        """
        self._threshold = int(threshold)
        self._block_time = int(block_time)
        self._trusted_keys = set(trusted_keys) if trusted_keys else None
        self._store = store or SelfCleaningInMemoryAuthenticationAttemptsStore(
            max_entry_age=self._block_time + 5
        )
        self._key_getter = key_getter

    def get_context_key(self, context: Any) -> str:
        """
        Extracts the rate limiting key from the authentication context.

        Raises an AuthException if no key_getter is provided. Custom extractors
        should be used carefully as they may introduce security vulnerabilities.
        """
        if not self._key_getter:
            return ""
        return self._key_getter(context)

    async def allow_authentication_attempt(self, context: Any) -> bool:
        """
        Determines if an authentication attempt should be allowed based on rate limiting
        rules. Returns True if the attempt should proceed, False if it should be
        blocked.
        """
        key = self.get_context_key(context)

        if not key:
            # BF protection disabled for backward compatibility.
            # This option will be deprecated in a future version.
            return True

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


class SelfCleaningInMemoryAuthenticationAttemptsStore(
    InMemoryAuthenticationAttemptsStore
):
    """
    Enhanced in-memory implementation with automatic cleanup of stale entries.

    Extends the base InMemoryAuthenticationAttemptsStore with lazy cleanup functionality
    to prevent memory leaks in long-running applications. Stale entries are
    automatically removed during normal operations at configurable intervals.
    """

    def __init__(self, cleanup_interval: int = 300, max_entry_age: int = 3600) -> None:
        """
        Initialize the self-cleaning store.

        Args:
            cleanup_interval: Seconds between cleanup checks (default: 5 minutes)
            max_entry_age: Maximum age of entries before cleanup, in seconds
                           (default: 1 hour)
        """
        super().__init__()
        self._cleanup_interval = cleanup_interval
        self._max_entry_age = max_entry_age
        self._last_cleanup = datetime.now(UTC)

    async def get_failed_attempts(
        self, key: str
    ) -> Optional[FailedAuthenticationAttempts]:
        await self._cleanup_if_needed()
        return await super().get_failed_attempts(key)

    async def set_failed_attempts(self, data: FailedAuthenticationAttempts) -> None:
        await self._cleanup_if_needed()
        await super().set_failed_attempts(data)

    async def _cleanup_if_needed(self) -> None:
        """Periodically remove stale entries during normal operations."""
        now = datetime.now(UTC)
        if (now - self._last_cleanup).total_seconds() >= self._cleanup_interval:
            await self._cleanup_stale_entries()
            self._last_cleanup = now

    async def _cleanup_stale_entries(self) -> None:
        """Remove entries older than max_entry_age."""
        stale_keys = [
            key
            for key, attempt in self._attempts.items()
            if attempt.get_age() >= self._max_entry_age
        ]

        for key in stale_keys:
            self._attempts.pop(key, None)
