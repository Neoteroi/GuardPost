"""
This example illustrates a basic use of an authorization strategy, with support for
dependency injection for authorization requirements.
"""
from __future__ import annotations

import asyncio

from neoteroi.di import Container

from neoteroi.auth import (
    AuthorizationContext,
    AuthorizationError,
    AuthorizationStrategy,
    Identity,
    Policy,
    Requirement,
    UnauthorizedError,
)


class Foo:
    ...


class MyInjectedRequirement(Requirement):
    foo: Foo

    def handle(self, context: AuthorizationContext):
        assert isinstance(self.foo, Foo)
        # EXAMPLE: implement here the desired notion / requirements for authorization
        #
        roles = context.identity["roles"]
        if roles and "ADMIN" in roles:
            context.succeed(self)
        else:
            context.fail("The user is not an ADMIN")


# NOTE: a Requirement.handle method can also be async!


async def main():
    container = Container()

    # NOTE: the following classes are registered as transient services - therefore
    # they are instantiated each time they are necessary.
    # Refer to neoteroi-di documentation to know how to register singletons and scoped
    # services.
    container.register(Foo)
    container.register(MyInjectedRequirement)

    authorization = AuthorizationStrategy(
        Policy("default", MyInjectedRequirement), container=container
    )

    await authorization.authorize(
        "default", Identity({"sub": "example", "roles": ["ADMIN"]})
    )

    auth_error = None

    try:
        await authorization.authorize(
            "default", Identity({"sub": "example", "roles": ["PEASANT"]})
        )
    except AuthorizationError as error:
        auth_error = error

    assert auth_error is not None
    assert isinstance(auth_error, UnauthorizedError)
    assert "The user is not an ADMIN." in str(auth_error)


asyncio.run(main())
