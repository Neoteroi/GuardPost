"""
This example illustrates a basic use of the authentication strategy, using more than
one way to obtain the user's identity.
"""
import asyncio

from neoteroi.auth import AuthenticationHandler, AuthenticationStrategy, Identity


class MyAppContext:
    """
    This represents a context for an application - it can be anything.
    """

    def __init__(self) -> None:
        self.identity: Identity | None = None


class CustomAuthenticationHandler(AuthenticationHandler):
    def authenticate(self, context: MyAppContext) -> "Identity | None":
        """
        In this example, we simulate a situation in which an identity cannot be
        determined for a context. Another Authenticationhandler
        """
        return None


class AlternativeAuthenticationHandler(AuthenticationHandler):
    def authenticate(self, context: MyAppContext) -> "Identity | None":
        return Identity({"sub": "002"})


async def main():
    some_context = MyAppContext()

    authentication = AuthenticationStrategy(
        CustomAuthenticationHandler(), AlternativeAuthenticationHandler()
    )

    identity = await authentication.authenticate(some_context)

    assert identity is not None
    assert identity.sub == "002"

    # the identity is set on the given context
    assert some_context.identity is identity


asyncio.run(main())
