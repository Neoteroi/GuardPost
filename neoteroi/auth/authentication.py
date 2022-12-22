from abc import ABC, abstractmethod
from typing import Any, List, Optional, Sequence


class Identity:
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
        return self.claims.get(item)

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
    async def authenticate(self, context: Any) -> Optional[Identity]:
        """Obtains an identity from a context."""


class AuthenticationSchemesNotFound(ValueError):
    def __init__(
        self, configured_schemes: Sequence[str], required_schemes: Sequence[str]
    ):
        super().__init__(
            "Could not find authentication handlers for required schemes: "
            f'{", ".join(required_schemes)}. '
            f'Configured schemes are: {", ".join(configured_schemes)}'
        )


class BaseAuthenticationStrategy(ABC):
    def __init__(self, *handlers: AuthenticationHandler):
        self.handlers = list(handlers)

    def add(self, handler: AuthenticationHandler) -> "BaseAuthenticationStrategy":
        self.handlers.append(handler)
        return self

    def __iadd__(self, handler: AuthenticationHandler) -> "BaseAuthenticationStrategy":
        self.handlers.append(handler)
        return self

    def get_handlers(
        self, authentication_schemes: Optional[Sequence[str]] = None
    ) -> List[AuthenticationHandler]:
        if not authentication_schemes:
            return self.handlers

        handlers = [
            handler
            for handler in self.handlers
            if handler.scheme in authentication_schemes
        ]

        if not handlers:
            raise AuthenticationSchemesNotFound(
                [handler.scheme for handler in self.handlers], authentication_schemes
            )

        return handlers

    @abstractmethod
    async def authenticate(
        self, context: Any, authentication_schemes: Optional[Sequence[str]] = None
    ):
        """
        Tries to obtain the user for a context, applying authentication rules.
        """


class AuthenticationStrategy(BaseAuthenticationStrategy):
    async def authenticate(
        self, context: Any, authentication_schemes: Optional[Sequence[str]] = None
    ):
        if not context:
            raise ValueError("Missing context to evaluate authentication")

        for handler in self.get_handlers(authentication_schemes):
            identity = await handler.authenticate(context)

            if identity:
                break
