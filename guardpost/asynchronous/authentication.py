from abc import abstractmethod
from typing import Any, Optional, Sequence

from guardpost.authentication import (
    BaseAuthenticationHandler,
    BaseAuthenticationStrategy,
    Identity,
)


class AuthenticationHandler(BaseAuthenticationHandler):
    @abstractmethod
    async def authenticate(self, context: Any) -> Optional[Identity]:
        """Obtains an identity from a context."""


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
