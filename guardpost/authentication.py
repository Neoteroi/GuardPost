import inspect
import logging
from abc import ABC, abstractmethod
from functools import lru_cache
from logging import Logger
from typing import Any, Callable, List, Optional, Sequence, Type, Union

from rodi import ContainerProtocol

from guardpost.abc import BaseStrategy
from guardpost.protection import InvalidCredentialsError, RateLimiter


class Identity:
    """
    Represents the characteristics of a person or a thing in the context of an
    application. It can be a user interacting with an app, or a technical account.
    """

    def __init__(
        self,
        claims: Optional[dict] = None,
        authentication_mode: Optional[str] = None,
    ):
        self.claims = claims or {}
        self.authentication_mode = authentication_mode
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None

    @property
    def sub(self) -> Optional[str]:
        return self.get("sub")

    @property
    def roles(self) -> Optional[str]:
        return self.get("roles")

    def is_authenticated(self) -> bool:
        return bool(self.authentication_mode)

    def get(self, key: str):
        return self.claims.get(key)

    def __getitem__(self, item):
        return self.claims[item]

    def has_claim(self, name: str) -> bool:
        return name in self.claims

    def has_claim_value(self, name: str, value: str) -> bool:
        return self.claims.get(name) == value

    def has_role(self, name: str) -> bool:
        if not self.roles:
            return False
        return name in self.roles


class User(Identity):
    @property
    def id(self) -> Optional[str]:
        return self.get("id") or self.sub

    @property
    def name(self) -> Optional[str]:
        return self.get("name")

    @property
    def email(self) -> Optional[str]:
        return self.get("email")


class AuthenticationHandler(ABC):
    """Base class for types that implement authentication logic."""

    @property
    def scheme(self) -> str:
        """Returns the name of the Authentication Scheme used by this handler."""
        return self.__class__.__name__

    @abstractmethod
    def authenticate(self, context: Any) -> Optional[Identity]:
        """Obtains an identity from a context."""


@lru_cache(maxsize=None)
def _is_async_handler(handler_type: Type[AuthenticationHandler]) -> bool:
    # Faster alternative to using inspect.iscoroutinefunction without caching
    # Note: this must be used on Types - not instances!
    return inspect.iscoroutinefunction(handler_type.authenticate)


AuthenticationHandlerConfType = Union[
    AuthenticationHandler, Type[AuthenticationHandler]
]


class AuthenticationSchemesNotFound(ValueError):
    def __init__(
        self, configured_schemes: Sequence[str], required_schemes: Sequence[str]
    ):
        super().__init__(
            "Could not find authentication handlers for required schemes: "
            f'{", ".join(required_schemes)}. '
            f'Configured schemes are: {", ".join(configured_schemes)}'
        )


class RateLimitingAuthenticationHandler(AuthenticationHandler):
    """
    An authentication handler that wraps another handler and applies rate limiting
    before delegating authentication.
    """

    def __init__(
        self,
        handler: AuthenticationHandler,
        rate_limiter: Optional[RateLimiter] = None,
        key_extractor: Optional[Callable[[Any], str]] = None,
        logger: Optional[Logger] = None,
    ):
        self._inner_handler = handler
        self._rate_limiter = rate_limiter or RateLimiter()
        self._key_extractor = key_extractor or self.default_key_extractor
        self._logger = logger or logging.getLogger("guardpost")

    @property
    def scheme(self) -> str:
        """Returns the name of the inner authentication handler's scheme."""
        return self._inner_handler.scheme

    @property
    def inner_handler(self) -> AuthenticationHandler:
        """Returns the inner authentication handler."""
        return self._inner_handler

    def default_key_extractor(self, context: Any) -> str:
        """
        Extract a key for rate limiting from the context.
        By default, it tries to read the `client_ip` attribute from the context.
        """
        try:
            return context.client_ip
        except AttributeError as ae:
            raise TypeError(
                "Cannot read 'client_ip' from the authentication context. "
                "Specify a key_extractor for your context to resolve this issue."
            ) from ae

    async def authenticate(self, context: Any) -> Optional[Identity]:  # type: ignore
        """Applies rate limiting then delegates to the inner handler."""
        key = self._key_extractor(context)

        # Check if this context is allowed to authenticate
        valid_context = await self._rate_limiter.allow_authentication_attempt(key)
        if not valid_context:
            return None

        try:
            # Delegate to the actual handler
            if _is_async_handler(type(self._inner_handler)):
                return await self._inner_handler.authenticate(context)  # type: ignore
            else:
                return self._inner_handler.authenticate(context)

        except InvalidCredentialsError as error:
            # Store the failure information
            self._logger.info(
                "Invalid credentials received for key %s using scheme: %s",
                key,
                self.scheme,
            )

            # Ensure the error has the right key for rate limiting
            error.key = key  # Make sure InvalidCredentialsError has a key attribute
            await self._rate_limiter.store_failure(error)

            # Do not raise, as next authentication handlers might succeed


class AuthenticationStrategy(BaseStrategy):
    def __init__(
        self,
        *handlers: AuthenticationHandlerConfType,
        container: Optional[ContainerProtocol] = None,
        rate_limiter: Optional[RateLimiter] = None,
        logger: Optional[Logger] = None,
    ):
        super().__init__(container)
        self.handlers = list(handlers)
        self._rate_limiter = rate_limiter or RateLimiter()
        self._logger = logger or logging.getLogger("guardpost")

    def add(self, handler: AuthenticationHandlerConfType) -> "AuthenticationStrategy":
        self.handlers.append(handler)
        return self

    def __iadd__(
        self, handler: AuthenticationHandlerConfType
    ) -> "AuthenticationStrategy":
        self.handlers.append(handler)
        return self

    def _get_handlers_by_schemes(
        self,
        authentication_schemes: Optional[Sequence[str]] = None,
        context: Any = None,
    ) -> List[AuthenticationHandler]:
        if not authentication_schemes:
            return list(self._get_instances(self.handlers, context))

        handlers = [
            handler
            for handler in self._get_instances(self.handlers, context)
            if handler.scheme in authentication_schemes
        ]

        if not handlers:
            raise AuthenticationSchemesNotFound(
                [
                    handler.scheme
                    for handler in self._get_instances(self.handlers, context)
                ],
                authentication_schemes,
            )

        return handlers

    async def authenticate(
        self, context: Any, authentication_schemes: Optional[Sequence[str]] = None
    ) -> Optional[Identity]:
        """
        Tries to obtain the user for a context, applying authentication rules.
        """
        if not context:
            raise ValueError("Missing context to evaluate authentication")

        # TODO: how to apply rate limiting by username and client_ip here?
        # We should probably lock a user account from a certain IP and user account
        # combination and not from any IP in general???
        # Maybe this should be checked for each authentication handler?
        valid_context = await self._rate_limiter.allow_authentication_attempt(context)

        if not valid_context:
            # TODO: raise specific exception?
            return None

        identity = None
        for handler in self._get_handlers_by_schemes(authentication_schemes, context):
            try:
                identity = await self._authenticate_with_handler(handler, context)
            except InvalidCredentialsError as invalid_credentials_error:
                # A client provided credentials of a given type, and they were invalid.
                # Store the information, so later we can verify.
                self._logger.info(
                    "Invalid credentials received from client IP %s for scheme: %s",
                    invalid_credentials_error.client_ip,
                    handler.scheme,
                )
                await self._rate_limiter.store_failure(invalid_credentials_error)

            if identity:
                try:
                    context.identity = identity
                except AttributeError:
                    pass
                return identity
        return None

    def apply_rate_limiting(
        self,
        schemes: Optional[List[str]] = None,
        rate_limiter: Optional[RateLimiter] = None,
        key_extractor: Optional[Callable[[Any], str]] = None,
    ) -> None:
        """Applies rate limiting to all handlers or specific handlers."""
        limiter = rate_limiter or self._rate_limiter

        # Get handlers to apply rate limiting to
        handlers_to_wrap = []
        if schemes:
            handlers_to_wrap = [h for h in self.handlers if h.scheme in schemes]
        else:
            handlers_to_wrap = self.handlers.copy()

        # Replace handlers with rate-limited versions
        for i, handler in enumerate(self.handlers):
            if handler in handlers_to_wrap:
                self.handlers[i] = RateLimitingAuthenticationHandler(
                    handler, rate_limiter=limiter, key_extractor=key_extractor
                )

    async def _authenticate_with_handler(self, handler: AuthenticationHandler, context):
        if _is_async_handler(type(handler)):
            return await handler.authenticate(context)  # type: ignore
        else:
            return handler.authenticate(context)
