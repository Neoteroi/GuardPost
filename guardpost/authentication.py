import inspect
import logging
from abc import ABC, abstractmethod
from functools import lru_cache
from logging import Logger
from typing import Any, List, Optional, Sequence, Type, Union

from rodi import ContainerProtocol

from guardpost.abc import BaseStrategy
from guardpost.errors import TooManyAuthenticationAttemptsError
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

        valid_context = await self._rate_limiter.allow_authentication_attempt(context)

        if not valid_context:
            raise TooManyAuthenticationAttemptsError()

        identity = None
        for handler in self._get_handlers_by_schemes(authentication_schemes, context):
            try:
                identity = await self._authenticate_with_handler(handler, context)
            except InvalidCredentialsError as invalid_credentials_error:
                # A client provided credentials of a given type, and they were invalid.
                # Store the information, so later calls can be validated without
                # attempting authentication.
                self._logger.info(
                    "Invalid credentials received from client IP %s for scheme: %s",
                    invalid_credentials_error.client_ip,
                    handler.scheme,
                )
                await self._rate_limiter.store_authentication_failure(
                    invalid_credentials_error
                )

            if identity:
                try:
                    context.identity = identity
                except AttributeError:
                    pass
                return identity
            else:
                if context.identity is None:
                    context.identity = Identity()
        return None

    async def _authenticate_with_handler(self, handler: AuthenticationHandler, context):
        if _is_async_handler(type(handler)):
            return await handler.authenticate(context)  # type: ignore
        else:
            return handler.authenticate(context)
