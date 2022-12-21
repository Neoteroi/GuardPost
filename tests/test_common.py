from typing import Any, Optional

from pytest import raises

from neoteroi.auth.authentication import Identity
from neoteroi.auth.authorization import Policy, UnauthorizedError
from neoteroi.auth.common import AnonymousPolicy, AuthenticatedRequirement
from neoteroi.auth.synchronous.authentication import (
    AuthenticationHandler,
    AuthenticationStrategy,
)
from neoteroi.auth.synchronous.authorization import AuthorizationStrategy


def test_policy_without_requirements_always_succeeds():
    # a policy without requirements is a no-op policy that always succeeds,
    # even when there is no known identity
    strategy = AuthorizationStrategy(Policy("default"))

    strategy.authorize("default", None)

    strategy.authorize("default", Identity({}))

    assert True


def test_anonymous_policy():
    strategy = AuthorizationStrategy(default_policy=AnonymousPolicy())

    strategy.authorize(None, None)

    strategy.authorize(None, Identity({}))

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
        ValueError, match="Only requirements can be added using __iadd__ syntax"
    ):
        strategy.default_policy += object()


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
