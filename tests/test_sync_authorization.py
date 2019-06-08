from pytest import raises
from typing import Sequence
from tests.examples import Request, NoopRequirement
from guardpost.authentication import User
from guardpost.authorization import Policy, PolicyNotFoundError
from guardpost.synchronous.authorization import (Requirement,
                                                 UnauthorizedError,
                                                 AuthorizationContext,
                                                 AuthorizationStrategy,
                                                 AuthenticatedRequirement)


def empty_identity_getter(_):
    return None


def get_strategy(policies: Sequence[Policy], identity_getter=None):
    if identity_getter is None:
        identity_getter = empty_identity_getter
    return AuthorizationStrategy(identity_getter, *policies)


def request_identity_getter(args):
    return args.get('request').user


def test_authorization_identity_getter():

    class UserNameRequirement(Requirement):

        def __init__(self, expected_name: str):
            self.expected_name = expected_name

        def handle(self, context: AuthorizationContext):
            assert context.identity is not None

            if context.identity.has_claim_value('name', self.expected_name):
                context.succeed(self)

    auth = get_strategy([Policy('user', UserNameRequirement('Tybek'))], request_identity_getter)

    @auth(policy='user')
    def some_method(request: Request):
        assert request is not None
        return True

    value = some_method(Request(None, User({
        'name': 'Tybek'
    })))

    assert value is True


def test_policy_not_found_error_sync():
    auth = get_strategy([Policy('admin')])

    @auth(policy='user')
    def some_method():
        pass

    with raises(PolicyNotFoundError, match='Cannot find policy'):
        some_method()


def test_policy_authorization_two_requirements_both_fail():

    class ExampleOne(Requirement):

        def handle(self, context: AuthorizationContext):
            pass

    class ExampleTwo(Requirement):

        def handle(self, context: AuthorizationContext):
            pass

    auth = get_strategy([Policy('user', ExampleOne(), ExampleTwo())])

    @auth(policy='user')
    def some_method():
        return True

    with raises(UnauthorizedError, match='The user is not authorized to perform the selected action. '
                                         'Failed requirements: ExampleOne, ExampleTwo.'):
        some_method()


def test_auth_without_policy_no_identity():
    auth: AuthorizationStrategy = get_strategy([])

    @auth()
    def some_method():
        return True

    with raises(UnauthorizedError, match='Missing identity'):
        some_method()


def test_auth_using_default_policy_failing():
    auth: AuthorizationStrategy = get_strategy([])

    auth.default_policy = Policy('authenticated', AuthenticatedRequirement())

    @auth()
    def some_method():
        return True

    with raises(UnauthorizedError):
        some_method()


def test_auth_using_default_policy_succeeding():
    auth: AuthorizationStrategy = get_strategy([])

    auth.default_policy = Policy('noop', NoopRequirement())

    @auth()
    def some_method():
        return True

    assert some_method()


def test_auth_without_policy_anonymous_identity():
    auth: AuthorizationStrategy = get_strategy([], lambda _: User({'oid': '001'}))

    @auth()
    def some_method():
        return True

    with raises(UnauthorizedError, match='The resource requires authentication'):
        some_method()
