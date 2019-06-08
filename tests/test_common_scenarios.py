from guardpost.authorization import Policy
from guardpost.authentication import Identity
from guardpost.synchronous.authorization import AuthorizationStrategy
from guardpost.common import AnonymousPolicy, ClaimsRequirement, AuthenticatedRequirement


def test_policy_without_requirements_always_succeeds():
    # a policy without requirements is a no-op policy that always succeeds,
    # even when there is no known identity
    strategy = AuthorizationStrategy(Policy('default'))

    strategy.authorize('default', None)

    strategy.authorize('default', Identity({}))

    assert True


def test_anonymous_policy():
    strategy = AuthorizationStrategy(default_policy=AnonymousPolicy())

    strategy.authorize(None, None)

    strategy.authorize(None, Identity({}))

    assert True
