"""
This example illustrates a basic use of the authentication strategy, showing how
authentication handlers can be grouped by authentication schemes.
"""
import asyncio

from neoteroi.auth import AuthenticationHandler, AuthenticationStrategy, Identity


class MyAppContext:
    """
    This represents a context for an application - it can be anything depending on
    use cases and the user's notion of application context.
    """

    def __init__(self) -> None:
        self.identity: Identity | None = None


class AuthenticationHandlerOne(AuthenticationHandler):
    @property
    def scheme(self) -> str:
        return "one"

    def authenticate(self, context: MyAppContext) -> "Identity | None":
        return Identity({"sub": "001"}, self.scheme)


class AuthenticationHandlerTwo(AuthenticationHandler):
    @property
    def scheme(self) -> str:
        return "two"

    def authenticate(self, context: MyAppContext) -> "Identity | None":
        return Identity({"sub": "002"}, self.scheme)


async def main():
    authentication = AuthenticationStrategy(
        AuthenticationHandlerOne(), AuthenticationHandlerTwo()
    )

    for scheme in ["one", "two"]:
        some_context = MyAppContext()

        identity = await authentication.authenticate(some_context, [scheme])

        assert identity is not None
        assert identity.authentication_mode == scheme

        assert some_context.identity is identity


asyncio.run(main())
