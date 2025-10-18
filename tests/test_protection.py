from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock

import pytest

from guardpost.errors import InvalidCredentialsError
from guardpost.protection import (
    AuthenticationAttemptsStore,
    FailedAuthenticationAttempts,
    InMemoryAuthenticationAttemptsStore,
    RateLimiter,
    SelfCleaningInMemoryAuthenticationAttemptsStore,
)


UTC = timezone.utc  # for Python 3.10 support…


class TestFailedAuthenticationAttempts:
    def test_init(self):
        key = "192.168.1.1"
        attempts = FailedAuthenticationAttempts(key)

        assert attempts.key == key
        assert attempts.counter == 1
        assert isinstance(attempts.last_attempt_time, datetime)
        assert attempts.last_attempt_time.tzinfo == UTC

    def test_increase_counter(self):
        attempts = FailedAuthenticationAttempts("test_key")
        initial_time = attempts.last_attempt_time

        # Small delay to ensure time difference
        import time

        time.sleep(0.01)

        result = attempts.increase_counter()

        assert result == 2
        assert attempts.counter == 2
        assert attempts.last_attempt_time > initial_time

    def test_multiple_increases(self):
        attempts = FailedAuthenticationAttempts("test_key")

        for i in range(1, 6):
            result = attempts.increase_counter()
            assert result == i + 1
            assert attempts.counter == i + 1

    def test_get_age(self):
        attempts = FailedAuthenticationAttempts("test_key")

        # Test that age is very small for a fresh attempt
        age = attempts.get_age()
        assert 0 <= age < 1

        # Mock an older attempt
        old_time = datetime.now(UTC) - timedelta(seconds=30)
        attempts._last_attempt_time = old_time

        age = attempts.get_age()
        assert 29 <= age <= 31  # Allow some tolerance for execution time


class TestInMemoryAuthenticationAttemptsStore:
    @pytest.fixture
    def store(self):
        return InMemoryAuthenticationAttemptsStore()

    @pytest.mark.asyncio
    async def test_get_nonexistent_attempts(self, store):
        result = await store.get_failed_attempts("nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_set_and_get_attempts(self, store):
        attempts = FailedAuthenticationAttempts("test_key")
        attempts.increase_counter()

        await store.set_failed_attempts(attempts)

        retrieved = await store.get_failed_attempts("test_key")
        assert retrieved is not None
        assert retrieved.key == "test_key"
        assert retrieved.counter == 2

    @pytest.mark.asyncio
    async def test_clear_attempts(self, store):
        attempts = FailedAuthenticationAttempts("test_key")
        await store.set_failed_attempts(attempts)

        # Verify it exists
        retrieved = await store.get_failed_attempts("test_key")
        assert retrieved is not None

        # Clear and verify it's gone
        await store.clear_attempts("test_key")
        retrieved = await store.get_failed_attempts("test_key")
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_multiple_keys(self, store):
        attempts1 = FailedAuthenticationAttempts("key1")
        attempts2 = FailedAuthenticationAttempts("key2")

        attempts1.increase_counter()
        attempts2.increase_counter()
        attempts2.increase_counter()

        await store.set_failed_attempts(attempts1)
        await store.set_failed_attempts(attempts2)

        retrieved1 = await store.get_failed_attempts("key1")
        retrieved2 = await store.get_failed_attempts("key2")

        assert retrieved1.counter == 2
        assert retrieved2.counter == 3


class TestRateLimiter:
    def key_getter(self, context):
        return context.get("ip", "")

    @pytest.fixture
    def basic_limiter(self):
        return RateLimiter(key_getter=self.key_getter, threshold=3, block_time=60)

    def test_init_with_defaults(self):
        limiter = RateLimiter(key_getter=self.key_getter)

        assert limiter._threshold == 20
        assert limiter._block_time == 60
        assert limiter._trusted_keys is None
        assert isinstance(limiter._store, InMemoryAuthenticationAttemptsStore)

    def test_init_with_custom_store(self):
        mock_store = AsyncMock(spec=AuthenticationAttemptsStore)
        limiter = RateLimiter(key_getter=self.key_getter, store=mock_store)

        assert limiter._store is mock_store

    def test_init_with_trusted_keys(self):
        trusted = ["127.0.0.1", "192.168.1.100"]
        limiter = RateLimiter(key_getter=self.key_getter, trusted_keys=trusted)

        assert limiter._trusted_keys == set(trusted)

    def test_get_context_key(self, basic_limiter):
        context = {"ip": "192.168.1.1"}
        key = basic_limiter.get_context_key(context)
        assert key == "192.168.1.1"

    @pytest.mark.asyncio
    async def test_allow_authentication_attempt_trusted_key(self):
        limiter = RateLimiter(key_getter=self.key_getter, trusted_keys=["192.168.1.1"])

        context = {"ip": "192.168.1.1"}
        result = await limiter.allow_authentication_attempt(context)
        assert result is True

    @pytest.mark.asyncio
    async def test_allow_authentication_attempt_no_previous_failures(
        self, basic_limiter
    ):
        context = {"ip": "192.168.1.1"}
        result = await basic_limiter.allow_authentication_attempt(context)
        assert result is True

    @pytest.mark.asyncio
    async def test_allow_authentication_attempt_under_threshold(self, basic_limiter):
        # Set up a failed attempt under threshold
        attempts = FailedAuthenticationAttempts("192.168.1.1")
        attempts.increase_counter()  # 2 attempts, threshold is 3

        await basic_limiter._store.set_failed_attempts(attempts)

        context = {"ip": "192.168.1.1"}
        result = await basic_limiter.allow_authentication_attempt(context)
        assert result is True

    @pytest.mark.asyncio
    async def test_allow_authentication_attempt_over_threshold(self, basic_limiter):
        # Set up failed attempts over threshold
        attempts = FailedAuthenticationAttempts("192.168.1.1")
        for _ in range(4):  # 4 attempts, threshold is 3
            attempts.increase_counter()

        await basic_limiter._store.set_failed_attempts(attempts)

        context = {"ip": "192.168.1.1"}
        result = await basic_limiter.allow_authentication_attempt(context)
        assert result is False

    @pytest.mark.asyncio
    async def test_allow_authentication_attempt_expired_block(self, basic_limiter):
        # Set up old failed attempts that should be expired
        attempts = FailedAuthenticationAttempts("192.168.1.1")
        for _ in range(4):  # Over threshold
            attempts.increase_counter()

        # Make the attempts old enough to be expired
        old_time = datetime.now(UTC) - timedelta(seconds=120)  # block_time is 60
        attempts._last_attempt_time = old_time

        await basic_limiter._store.set_failed_attempts(attempts)

        context = {"ip": "192.168.1.1"}
        result = await basic_limiter.allow_authentication_attempt(context)
        assert result is True

        # Verify the old attempts were cleared
        cleared_attempts = await basic_limiter._store.get_failed_attempts("192.168.1.1")
        assert cleared_attempts is None

    @pytest.mark.asyncio
    async def test_store_authentication_failure_new_key(self, basic_limiter):
        error = InvalidCredentialsError("Invalid credentials", "192.168.1.1")

        await basic_limiter.store_authentication_failure(error)

        attempts = await basic_limiter._store.get_failed_attempts("192.168.1.1")
        assert attempts is not None
        assert attempts.counter == 1  # New attempt starts at 1, then increases

    @pytest.mark.asyncio
    async def test_store_authentication_failure_existing_key(self, basic_limiter):
        # Set up existing attempts
        existing_attempts = FailedAuthenticationAttempts("192.168.1.1")
        existing_attempts.increase_counter()
        await basic_limiter._store.set_failed_attempts(existing_attempts)

        error = InvalidCredentialsError("Invalid credentials", "192.168.1.1")
        await basic_limiter.store_authentication_failure(error)

        attempts = await basic_limiter._store.get_failed_attempts("192.168.1.1")
        assert attempts.counter == 3

    @pytest.mark.asyncio
    async def test_store_authentication_failure_expired_existing(self, basic_limiter):
        # Set up old existing attempts
        existing_attempts = FailedAuthenticationAttempts("192.168.1.1")
        existing_attempts.increase_counter()
        old_time = datetime.now(UTC) - timedelta(seconds=120)  # Expired
        existing_attempts._last_attempt_time = old_time
        await basic_limiter._store.set_failed_attempts(existing_attempts)

        error = InvalidCredentialsError("Invalid credentials", "192.168.1.1")
        await basic_limiter.store_authentication_failure(error)

        attempts = await basic_limiter._store.get_failed_attempts("192.168.1.1")
        assert attempts.counter == 1  # Reset because old attempts expired

    @pytest.mark.asyncio
    async def test_integration_flow(self, basic_limiter):
        context = {"ip": "192.168.1.1"}

        # First few attempts should be allowed
        for i in range(3):
            result = await basic_limiter.allow_authentication_attempt(context)
            assert result is True

            # Simulate failed login
            error = InvalidCredentialsError("Invalid", "192.168.1.1")
            await basic_limiter.store_authentication_failure(error)

        # After threshold reached, should be blocked
        result = await basic_limiter.allow_authentication_attempt(context)
        assert result is False

        # Even more attempts should still be blocked
        result = await basic_limiter.allow_authentication_attempt(context)
        assert result is False

    def test_integer_conversion(self):
        # Test that threshold and block_time are converted to integers
        limiter = RateLimiter(
            key_getter=self.key_getter, threshold=5.7, block_time=60.9
        )

        assert limiter._threshold == 5
        assert limiter._block_time == 60


class TestSelfCleaningInMemoryAuthenticationAttemptsStore:
    @pytest.fixture
    def store(self):
        return SelfCleaningInMemoryAuthenticationAttemptsStore(
            cleanup_interval=1, max_entry_age=5
        )

    @pytest.fixture
    def long_cleanup_store(self):
        return SelfCleaningInMemoryAuthenticationAttemptsStore(
            cleanup_interval=300, max_entry_age=60
        )

    def test_init_defaults(self):
        store = SelfCleaningInMemoryAuthenticationAttemptsStore()

        assert store._cleanup_interval == 300
        assert store._max_entry_age == 3600
        assert isinstance(store._last_cleanup, datetime)

    def test_init_custom_values(self):
        store = SelfCleaningInMemoryAuthenticationAttemptsStore(
            cleanup_interval=60, max_entry_age=120
        )

        assert store._cleanup_interval == 60
        assert store._max_entry_age == 120

    @pytest.mark.asyncio
    async def test_inherits_basic_functionality(self, store):
        # Test that it still works like the base class
        attempts = FailedAuthenticationAttempts("test_key")
        await store.set_failed_attempts(attempts)

        retrieved = await store.get_failed_attempts("test_key")
        assert retrieved is not None
        assert retrieved.key == "test_key"

    @pytest.mark.asyncio
    async def test_cleanup_removes_stale_entries(self, store):
        # Add some attempts and make them stale
        attempts1 = FailedAuthenticationAttempts("stale_key")
        attempts2 = FailedAuthenticationAttempts("fresh_key")

        # Make attempts1 stale by setting old timestamp
        old_time = datetime.now(UTC) - timedelta(seconds=10)
        attempts1._last_attempt_time = old_time

        await store.set_failed_attempts(attempts1)
        await store.set_failed_attempts(attempts2)

        # Verify both exist
        assert await store.get_failed_attempts("stale_key") is not None
        assert await store.get_failed_attempts("fresh_key") is not None

        # Force cleanup by calling the private method
        await store._cleanup_stale_entries()

        # Stale entry should be gone, fresh should remain
        assert await store.get_failed_attempts("stale_key") is None
        assert await store.get_failed_attempts("fresh_key") is not None

    @pytest.mark.asyncio
    async def test_cleanup_triggered_by_time_interval(self, long_cleanup_store):
        # Set up old cleanup time to force cleanup on next operation
        old_cleanup_time = datetime.now(UTC) - timedelta(seconds=400)
        long_cleanup_store._last_cleanup = old_cleanup_time

        # Add a stale entry
        attempts = FailedAuthenticationAttempts("stale_key")
        old_time = datetime.now(UTC) - timedelta(
            seconds=120
        )  # Older than max_entry_age
        attempts._last_attempt_time = old_time
        long_cleanup_store._attempts["stale_key"] = attempts

        # Trigger cleanup through normal operation
        await long_cleanup_store.get_failed_attempts("any_key")

        # Stale entry should be cleaned up
        assert "stale_key" not in long_cleanup_store._attempts

        # Last cleanup time should be updated
        assert long_cleanup_store._last_cleanup > old_cleanup_time

    @pytest.mark.asyncio
    async def test_cleanup_not_triggered_within_interval(self, store):
        # Set recent cleanup time
        store._last_cleanup = datetime.now(UTC)

        # Add a stale entry manually
        attempts = FailedAuthenticationAttempts("stale_key")
        old_time = datetime.now(UTC) - timedelta(seconds=10)
        attempts._last_attempt_time = old_time
        store._attempts["stale_key"] = attempts

        # Operation should not trigger cleanup due to recent cleanup time
        await store.get_failed_attempts("any_key")

        # Stale entry should still exist (cleanup wasn't triggered)
        assert "stale_key" in store._attempts

    @pytest.mark.asyncio
    async def test_cleanup_during_set_operation(self, long_cleanup_store):
        # Force cleanup trigger
        old_cleanup_time = datetime.now(UTC) - timedelta(seconds=400)
        long_cleanup_store._last_cleanup = old_cleanup_time

        # Add stale entry manually
        stale_attempts = FailedAuthenticationAttempts("stale_key")
        old_time = datetime.now(UTC) - timedelta(seconds=120)
        stale_attempts._last_attempt_time = old_time
        long_cleanup_store._attempts["stale_key"] = stale_attempts

        # Trigger cleanup through set operation
        new_attempts = FailedAuthenticationAttempts("new_key")
        await long_cleanup_store.set_failed_attempts(new_attempts)

        # New entry should exist, stale should be gone
        assert await long_cleanup_store.get_failed_attempts("new_key") is not None
        assert "stale_key" not in long_cleanup_store._attempts

    @pytest.mark.asyncio
    async def test_cleanup_preserves_non_stale_entries(self, store):
        # Add mix of stale and fresh entries
        stale_attempts = FailedAuthenticationAttempts("stale_key")
        fresh_attempts1 = FailedAuthenticationAttempts("fresh_key1")
        fresh_attempts2 = FailedAuthenticationAttempts("fresh_key2")

        # Make one stale
        old_time = datetime.now(UTC) - timedelta(seconds=10)
        stale_attempts._last_attempt_time = old_time

        store._attempts["stale_key"] = stale_attempts
        store._attempts["fresh_key1"] = fresh_attempts1
        store._attempts["fresh_key2"] = fresh_attempts2

        await store._cleanup_stale_entries()

        # Only stale should be removed
        assert "stale_key" not in store._attempts
        assert "fresh_key1" in store._attempts
        assert "fresh_key2" in store._attempts

    @pytest.mark.asyncio
    async def test_empty_store_cleanup(self, store):
        # Cleanup should work fine on empty store
        await store._cleanup_stale_entries()
        assert len(store._attempts) == 0

        # Should still work after cleanup
        attempts = FailedAuthenticationAttempts("test_key")
        await store.set_failed_attempts(attempts)
        assert await store.get_failed_attempts("test_key") is not None
