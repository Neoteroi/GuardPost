from abc import ABC, abstractmethod
from typing import Any, Optional
from guardpost.authentication import Identity


class AuthenticationHandler(ABC):

    @abstractmethod
    async def authenticate(self, context: Any) -> Optional[Identity]:
        """Obtains an identity from a context."""


class AuthenticationStrategy:

    def __init__(self, *handlers: AuthenticationHandler):
        self.handlers = handlers

    async def authenticate(self, context: Any):
        if not context:
            raise ValueError('Missing context to evaluate authentication')

        for handler in self.handlers:
            identity = await handler.authenticate(context)

            if identity:
                break
