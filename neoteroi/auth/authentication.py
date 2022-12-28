import inspect
from abc import ABC, abstractmethod
from functools import lru_cache
from typing import Any, List, Optional, Sequence, Type, Union

from neoteroi.di import ContainerProtocol

from neoteroi.auth.abc import BaseStrategy


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
        return self["sub"]

    def is_authenticated(self) -> bool:
        return bool(self.authentication_mode)

    def __getitem__(self, item):
        return self.claims[item]

    def has_claim(self, name: str) -> bool:
        return name in self.claims

    def has_claim_value(self, name: str, value: str) -> bool:
        return self.claims.get(name) == value


class User(Identity):
    @property
    def id(self) -> Optional[str]:
        return self["id"] or self.sub

    @property
    def name(self) -> Optional[str]:
        return self["name"]

    @property
    def email(self) -> Optional[str]:
        return self["email"]


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
    ):
        super().__init__(container)
        self.handlers = list(handlers)

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

        for handler in self._get_handlers_by_schemes(authentication_schemes, context):
            if _is_async_handler(type(handler)):
                identity = await handler.authenticate(context)  # type: ignore
            else:
                identity = handler.authenticate(context)

            if identity:
                try:
                    context.identity = identity
                except AttributeError:
                    pass
                return identity
        return None
