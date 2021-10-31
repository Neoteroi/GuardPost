from abc import abstractmethod
from typing import Any, Optional, Sequence

from guardpost.authentication import (
    BaseAuthenticationHandler,
    BaseAuthenticationStrategy,
    Identity,
)


class AuthenticationHandler(BaseAuthenticationHandler):
    @abstractmethod
    def authenticate(self, context: Any) -> Optional[Identity]:
        """Obtains an identity from a context."""


class AuthenticationStrategy(BaseAuthenticationStrategy):
    def authenticate(
        self, context: Any, authentication_schemes: Optional[Sequence[str]] = None
    ):
        if not context:
            raise ValueError("Missing context to evaluate authentication")

        for handler in self.get_handlers(authentication_schemes):
            identity = handler.authenticate(context)

            if identity:
                break
