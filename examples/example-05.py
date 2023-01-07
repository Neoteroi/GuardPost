"""
This example illustrates a basic use of an authorization strategy.
"""
from __future__ import annotations

import asyncio

from guardpost import (
    AuthorizationContext,
    AuthorizationError,
    AuthorizationStrategy,
    Identity,
    Policy,
    Requirement,
    UnauthorizedError,
)


class MyRequirement(Requirement):
    def handle(self, context: AuthorizationContext):
        # EXAMPLE: implement here the desired notion / requirements for authorization
        #
        roles = context.identity["roles"]
        if roles and "ADMIN" in roles:
            context.succeed(self)
        else:
            context.fail("The user is not an ADMIN")


# NOTE: a Requirement.handle method can also be async!


async def main():
    authorization = AuthorizationStrategy(Policy("default", MyRequirement()))

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
