"""
This example illustrates a basic use of the authentication strategy, using a single
authentication handler.
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


class CustomAuthenticationHandler(AuthenticationHandler):
    def authenticate(self, context: MyAppContext) -> "Identity | None":
        """
        Obtains an identity for a context.

        For example, this might read information from a user's folder, an HTTP Request
        cookie or authorization header, or an external service. This method can be
        either synchronous or asynchronous.
        """

        return Identity({"sub": "example"})


# NOTE: a AuthenticationHandler.authenticate method can also be async!


async def main():
    some_context = MyAppContext()

    authentication = AuthenticationStrategy(CustomAuthenticationHandler())

    identity = await authentication.authenticate(some_context)

    assert identity is not None
    assert identity.sub == "example"

    # the identity is set on the given context
    assert some_context.identity is identity


asyncio.run(main())
