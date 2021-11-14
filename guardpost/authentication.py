from abc import ABC
from typing import Optional, Sequence


class Identity:
    def __init__(
        self,
        claims: dict,
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


class BaseAuthenticationHandler(ABC):
    """Base class for authentication handlers"""

    @property
    def scheme(self) -> str:
        """Returns the name of the Authentication Scheme used by this handler."""
        return self.__class__.__name__


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
    def __init__(self, *handlers: BaseAuthenticationHandler):
        self.handlers = list(handlers)

    def add(self, handler: BaseAuthenticationHandler) -> "BaseAuthenticationStrategy":
        self.handlers.append(handler)
        return self

    def __iadd__(
        self, handler: BaseAuthenticationHandler
    ) -> "BaseAuthenticationStrategy":
        self.handlers.append(handler)
        return self

    def get_handlers(self, authentication_schemes: Optional[Sequence[str]] = None):
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
