"""
This example illustrates how to use an authorization strategy having more than one set
of criteria to handle authorization, and how to decorate methods so they require
authorization.
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
)
from guardpost.common import AuthenticatedRequirement


class MyAppContext:
    """
    This represents a context for an application - it can be anything depending on
    use cases and the user's notion of application context.
    """

    def __init__(self, identity: Identity) -> None:
        self.identity = identity


class RoleRequirement(Requirement):
    """Require a role to authorize an operation."""

    def __init__(self, role: str) -> None:
        self._role = role

    def handle(self, context: AuthorizationContext):
        # EXAMPLE: implement here the desired notion / requirements for authorization
        #
        roles = context.identity["roles"]
        if roles and self._role in roles:
            context.succeed(self)
        else:
            context.fail(f"The user lacks role: {self._role}")


# NOTE: a Requirement.handle method can also be async!


async def main():
    # In this example, we need to configure a function that can obtain the user identity
    # from the application context.

    def get_identity(context: MyAppContext):
        return context.identity

    auth = AuthorizationStrategy().with_default_policy(
        Policy("default", AuthenticatedRequirement())
    )

    auth.identity_getter = get_identity

    auth += Policy("admin", RoleRequirement("ADMIN"))
    auth += Policy("owner", RoleRequirement("OWNER"))

    @auth()
    async def some_method(context: MyAppContext):
        """Example method that requires authorization using the default policy."""

    @auth("owner")
    async def create_user(context: MyAppContext):
        """Example method that requires an OWNER role"""

    @auth("admin")
    async def create_product(context: MyAppContext):
        """Example method that requires an ADMIN role"""

    last_error: AuthorizationError | None = None

    # The following will cause an authorization error because the user identity is not
    # authenticated, and the default auth policy requires an authenticated user
    try:
        await some_method(MyAppContext(Identity()))
    except AuthorizationError as error:
        last_error = error

    assert last_error is not None

    last_error = None

    # The following will work because the context identity is authenticated with a mode
    await some_method(
        MyAppContext(
            Identity({"id": "this is an example"}, authentication_mode="Cookie")
        )
    )

    # The following will cause an authorization error because the user identity does
    # not have the proper role to create a user (OWNER).
    try:
        await create_user(
            MyAppContext(
                Identity(
                    {"id": "this is an example", "roles": ["admin"]},
                    authentication_mode="Cookie",
                )
            )
        )
    except AuthorizationError as error:
        last_error = error

    assert last_error is not None

    last_error = None

    # The following will cause an authorization error because the user identity does
    # not have the proper role to create a product (ADMIN).
    try:
        await create_product(
            MyAppContext(
                Identity(
                    {"id": "this is an example", "roles": ["admin"]},
                    authentication_mode="Cookie",
                )
            )
        )
    except AuthorizationError as error:
        last_error = error

    assert last_error is not None

    last_error = None


asyncio.run(main())
