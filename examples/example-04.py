"""
This example illustrates how dependency injection can be used for authentication
handlers.
"""
import asyncio

from neoteroi.di import Container

from neoteroi.auth import AuthenticationHandler, AuthenticationStrategy, Identity


class MyAppContext:
    """
    This represents a context for an application - it can be anything.
    """

    def __init__(self) -> None:
        self.identity: Identity | None = None


class Foo:
    """Example to illustrate dependency injection."""


class MyAuthenticationHandler(AuthenticationHandler):
    def __init__(self, foo: Foo) -> None:
        # foo will be injected
        self.foo = foo

    def authenticate(self, context: MyAppContext) -> Identity | None:
        assert isinstance(self.foo, Foo)
        return Identity({"sub": "001"}, self.scheme)


async def main():
    container = Container()

    container.register(Foo)
    container.register(MyAuthenticationHandler)

    authentication = AuthenticationStrategy(
        MyAuthenticationHandler, container=container
    )

    some_context = MyAppContext()

    identity = await authentication.authenticate(some_context)

    assert identity is not None


asyncio.run(main())
