from typing import Sequence

import pytest
from pytest import raises
from neoteroi.di import Container

from neoteroi.auth.authentication import Identity, User
from neoteroi.auth.authorization import (
    AuthorizationContext,
    AuthorizationStrategy,
    Policy,
    PolicyNotFoundError,
    Requirement,
    UnauthorizedError,
)
from neoteroi.auth.common import AuthenticatedRequirement, ClaimsRequirement
from tests.examples import NoopRequirement


def empty_identity_getter(*args, **kwargs):
    return Identity()


def no_identity_getter():
    return None


def get_strategy(policies: Sequence[Policy], identity_getter=None):
    if identity_getter is None:
        identity_getter = empty_identity_getter
    return AuthorizationStrategy(*policies, identity_getter=identity_getter)


@pytest.mark.asyncio
async def test_policy_not_found_error_sync():
    auth = get_strategy([Policy("admin")])

    @auth(policy="user")
    async def some_method():
        pass

    with raises(PolicyNotFoundError, match="Cannot find policy"):
        await some_method()


@pytest.mark.asyncio
async def test_policy_not_found_error_async():
    auth = get_strategy([Policy("admin")])

    @auth(policy="user")
    async def some_method():
        pass

    with raises(PolicyNotFoundError, match="Cannot find policy"):
        await some_method()


@pytest.mark.asyncio
async def test_policy_authorization_one_success():
    class Example(Requirement):
        async def handle(self, context: AuthorizationContext):
            context.succeed(self)

    auth = get_strategy([Policy("user", Example())])

    @auth(policy="user")
    async def some_method():
        return True

    value = await some_method()
    assert value is True, "Authorization succeeded"


@pytest.mark.asyncio
async def test_policy_authorization_one_success_class_method():
    class Example(Requirement):
        async def handle(self, context: AuthorizationContext):
            context.succeed(self)

    auth = get_strategy([Policy("user", Example())])

    class Foo:
        @auth(policy="user")
        async def some_method(self):
            return True

    context = Foo()

    value = await context.some_method()
    assert value is True, "Authorization succeeded"


@pytest.mark.asyncio
async def test_policy_authorization_two_requirements_both_fail():
    class ExampleOne(Requirement):
        async def handle(self, context: AuthorizationContext):
            pass

    class ExampleTwo(Requirement):
        async def handle(self, context: AuthorizationContext):
            pass

    auth = get_strategy([Policy("user", ExampleOne(), ExampleTwo())])

    @auth(policy="user")
    async def some_method():
        return True

    with raises(
        UnauthorizedError,
        match="The user is not authorized to perform the selected action. "
        "Failed requirements: ExampleOne, ExampleTwo.",
    ):
        await some_method()


@pytest.mark.asyncio
async def test_policy_authorization_two_requirements_one_fails():
    class ExampleOne(Requirement):
        async def handle(self, context: AuthorizationContext):
            context.succeed(self)

    class ExampleTwo(Requirement):
        async def handle(self, context: AuthorizationContext):
            pass

    auth = get_strategy([Policy("user", ExampleOne(), ExampleTwo())])

    @auth(policy="user")
    async def some_method():
        return True

    with raises(
        UnauthorizedError,
        match="The user is not authorized to perform the selected action. "
        "Failed requirements: ExampleTwo.",
    ):
        await some_method()


@pytest.mark.asyncio
async def test_policy_authorization_force_failure():
    class Example(Requirement):
        async def handle(self, context: AuthorizationContext):
            context.succeed(self)
            context.fail("Crash Test")  # <-- force failure

    auth = get_strategy([Policy("user", Example())])

    @auth(policy="user")
    async def some_method():
        pass

    with raises(UnauthorizedError, match="Crash Test"):
        await some_method()


class Request:
    def __init__(self, user):
        self.user = user


def request_identity_getter(request):
    return request.user


@pytest.mark.asyncio
async def test_authorization_identity_getter():
    class UserNameRequirement(Requirement):
        def __init__(self, expected_name: str):
            self.expected_name = expected_name

        async def handle(self, context: AuthorizationContext):
            assert context.identity is not None

            if context.identity.has_claim_value("name", self.expected_name):
                context.succeed(self)

    auth = get_strategy(
        [Policy("user", UserNameRequirement("Tybek"))], request_identity_getter
    )

    @auth(policy="user")
    async def some_method(request: Request):
        assert request is not None
        return True

    value = await some_method(Request(User({"name": "Tybek"})))

    assert value is True


@pytest.mark.asyncio
async def test_claims_requirement():
    auth = get_strategy(
        [Policy("x", ClaimsRequirement("name"))], request_identity_getter
    )

    @auth(policy="x")
    async def some_method(request: Request):
        assert request is not None
        return True

    value = await some_method(Request(User({"name": "Tybek"})))

    assert value is True


def test_policy_repr():
    policy = Policy("Cats lover")

    assert repr(policy).startswith('<Policy "Cats lover"')


def test_authenticated_requirement_succeeds_with_identity():
    requirement = AuthenticatedRequirement()

    context = AuthorizationContext(User({}, "oidc"), [requirement])

    requirement.handle(context)

    assert context.has_succeeded


def test_claims_requirement_fails_for_missing_identity():
    requirement = ClaimsRequirement("name")

    context = AuthorizationContext(None, [requirement])

    requirement.handle(context)

    assert context.forced_failure == "Missing identity"


def test_claims_requirement_mapping():
    requirement = ClaimsRequirement({"name": "Charlie"})

    context = AuthorizationContext(User({"name": "Charlie"}), [requirement])

    requirement.handle(context)

    assert context.has_succeeded

    context = AuthorizationContext(User({"name": "Sally"}), [requirement])

    requirement.handle(context)

    assert context.has_succeeded is False


@pytest.mark.asyncio
async def test_claims_requirement_mapping2():
    requirement = ClaimsRequirement({"name": "Charlie", "foo": "foo"})

    context = AuthorizationContext(
        User({"name": "Charlie", "foo": "foo"}), [requirement]
    )

    requirement.handle(context)

    assert context.has_succeeded

    context = AuthorizationContext(
        User({"name": "Charlie", "foo": "nope"}), [requirement]
    )

    requirement.handle(context)

    assert context.has_succeeded is False


@pytest.mark.asyncio
async def test_claims_requirement_sequence():
    requirement = ClaimsRequirement(["name", "foo"])

    context = AuthorizationContext(
        User({"name": "Charlie", "foo": "foo"}), [requirement]
    )

    requirement.handle(context)

    assert context.has_succeeded

    context = AuthorizationContext(
        User({"name": "Charlie", "ufo": "nope"}), [requirement]
    )

    requirement.handle(context)

    assert context.has_succeeded is False


@pytest.mark.asyncio
async def test_auth_without_policy_no_identity():
    auth: AuthorizationStrategy = get_strategy([])
    auth.identity_getter = no_identity_getter  # type: ignore

    @auth()
    async def some_method():
        return True

    with raises(UnauthorizedError, match="Missing identity"):
        await some_method()


@pytest.mark.asyncio
async def test_auth_using_default_policy_failing():
    auth: AuthorizationStrategy = get_strategy([])

    auth.default_policy = Policy("authenticated", AuthenticatedRequirement())

    @auth()
    async def some_method():
        return True

    with raises(UnauthorizedError):
        await some_method()


@pytest.mark.asyncio
async def test_auth_using_default_policy_succeeding():
    auth: AuthorizationStrategy = get_strategy([])

    auth.default_policy = Policy("noop", NoopRequirement())

    @auth()
    async def some_method():
        return True

    assert await some_method()


@pytest.mark.asyncio
async def test_auth_without_policy_anonymous_identity():
    auth: AuthorizationStrategy = get_strategy([], lambda: User({"oid": "001"}))

    @auth()
    async def some_method():
        return True

    with raises(UnauthorizedError, match="The resource requires authentication"):
        await some_method()


def test_unauthorized_error_message():
    ex = UnauthorizedError(None, None)

    assert str(ex) == "Unauthorized"


class Foo:
    pass


class InjectedRequirement(Requirement):
    service: Foo

    def handle(self, context):
        assert isinstance(self.service, Foo)
        context.succeed(self)


class ScopedTestRequirement1(Requirement):
    service_1: Foo
    service_2: Foo

    def handle(self, context):
        assert isinstance(self.service_1, Foo)
        assert self.service_1 is self.service_2
        context.succeed(self)


class ScopedTestRequirement2(Requirement):
    foo: Foo
    brother: ScopedTestRequirement1

    def handle(self, context):
        assert self.foo is self.brother.service_1
        context.succeed(self)


@pytest.mark.asyncio
async def test_authorization_di():
    container = Container()

    container.register(Foo)
    container.register(InjectedRequirement)  # TODO: auto register?

    auth = AuthorizationStrategy(
        Policy("example", InjectedRequirement), container=container
    )

    identity = Identity()
    assert await auth.authorize("example", identity) is None


@pytest.mark.asyncio
async def test_authorization_di_scoped():
    container = Container()

    container.add_scoped(Foo)
    container.register(ScopedTestRequirement1)
    container.register(ScopedTestRequirement2)

    auth = AuthorizationStrategy(
        Policy("example", ScopedTestRequirement1, ScopedTestRequirement2),
        container=container,
    )

    identity = Identity()
    assert await auth.authorize("example", identity) is None


@pytest.mark.asyncio
async def test_auth_raises_for_missing_identity_getter():
    auth: AuthorizationStrategy = get_strategy([])
    auth.identity_getter = None

    @auth()
    async def some_method():
        return True

    with raises(TypeError, match="Missing identity getter function."):
        await some_method()
