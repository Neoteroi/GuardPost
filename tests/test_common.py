from typing import Any, Optional

import pytest
from neoteroi.di import Container
from pytest import raises

from neoteroi.auth.abc import DINotConfiguredError
from neoteroi.auth.authentication import (
    AuthenticationHandler,
    AuthenticationStrategy,
    Identity,
)
from neoteroi.auth.authorization import AuthorizationStrategy, Policy, UnauthorizedError
from neoteroi.auth.common import AnonymousPolicy, AuthenticatedRequirement


@pytest.mark.asyncio
async def test_policy_without_requirements_always_succeeds():
    # a policy without requirements is a no-op policy that always succeeds,
    # even when there is no known identity
    strategy = AuthorizationStrategy(Policy("default"))

    await strategy.authorize("default", Identity())

    assert True


@pytest.mark.asyncio
async def test_anonymous_policy():
    strategy = AuthorizationStrategy(default_policy=AnonymousPolicy())

    await strategy.authorize(None, Identity())

    assert True


def test_policy_iadd_syntax():
    strategy = AuthorizationStrategy(default_policy=Policy("default"))

    auth_req = AuthenticatedRequirement()

    assert strategy.default_policy is not None
    strategy.default_policy += auth_req

    assert strategy.default_policy.requirements[0] is auth_req


def test_policy_iadd_syntax_raises_for_non_requirements():
    strategy = AuthorizationStrategy(default_policy=Policy("default"))

    with raises(
        ValueError,
        match="Only instances, or types, of Requirement can be added to the policy.",
    ):
        strategy.default_policy += object()  # type: ignore


def test_policy_add_method():
    strategy = AuthorizationStrategy(default_policy=Policy("default"))

    auth_req = AuthenticatedRequirement()

    strategy.default_policy.add(auth_req)

    assert strategy.default_policy.requirements[0] is auth_req


def test_authentication_strategy_iadd_method():
    strategy = AuthenticationStrategy()

    class ExampleOne(AuthenticationHandler):
        def authenticate(self, context: Any) -> Optional[Identity]:
            pass

    class ExampleTwo(AuthenticationHandler):
        def authenticate(self, context: Any) -> Optional[Identity]:
            pass

    one = ExampleOne()
    two = ExampleTwo()

    strategy += one

    assert strategy.handlers[0] is one

    strategy += two

    assert strategy.handlers[0] is one
    assert strategy.handlers[1] is two


def test_authentication_strategy_add_method():
    strategy = AuthenticationStrategy()

    class ExampleOne(AuthenticationHandler):
        def authenticate(self, context: Any) -> Optional[Identity]:
            pass

    class ExampleTwo(AuthenticationHandler):
        def authenticate(self, context: Any) -> Optional[Identity]:
            pass

    one = ExampleOne()
    two = ExampleTwo()

    strategy.add(one).add(two)

    assert strategy.handlers[0] is one
    assert strategy.handlers[1] is two


def test_authorization_strategy_add_method():
    strategy = AuthorizationStrategy()

    one = Policy("one")
    two = Policy("two")

    strategy.add(one).add(two)

    assert strategy.policies[0] is one
    assert strategy.policies[1] is two


def test_authorization_strategy_iadd_method():
    strategy = AuthorizationStrategy()

    one = Policy("one")
    two = Policy("two")

    strategy += one

    assert strategy.policies[0] is one

    strategy += two

    assert strategy.policies[0] is one
    assert strategy.policies[1] is two


def test_authorization_strategy_set_default_fluent():
    strategy = AuthorizationStrategy()

    policy = Policy("one")
    strategy.with_default_policy(policy)

    assert strategy.default_policy is policy


def test_unauthorized_error_supports_error_and_description():

    error = UnauthorizedError(
        None,
        [],
        scheme="Bearer",
        error="invalid token",
        error_description="The access token has expired",
    )

    assert error.scheme == "Bearer"
    assert error.error == "invalid token"
    assert error.error_description == "The access token has expired"


def test_strategy_set_container():
    strategy = AuthenticationStrategy()
    strategy.container = Container()


def test_container_getter_raises_for_missing_container():
    strategy = AuthenticationStrategy()

    with raises(DINotConfiguredError):
        strategy.container


def test_import_version():
    from neoteroi.auth.__about__ import __version__  # noqa
