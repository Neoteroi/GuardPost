from typing import Any, Optional
from uuid import uuid4

import pytest
from pytest import raises
from rodi import Container

from guardpost.authentication import (
    AuthenticationHandler,
    AuthenticationSchemesNotFound,
    AuthenticationStrategy,
    Identity,
    User,
)
from tests.examples import Request


def test_claims():
    a = Identity({"oid": "bc5f60df-4c27-49c1-8466-acf32618a6d2"})

    assert a.claims["oid"] == "bc5f60df-4c27-49c1-8466-acf32618a6d2"


def test_authenticated():
    a = Identity({"oid": "bc5f60df-4c27-49c1-8466-acf32618a6d2"}, "JWT Bearer")

    assert a.authentication_mode == "JWT Bearer"
    assert a.is_authenticated()


def test_not_authenticated():
    a = Identity({"oid": "bc5f60df-4c27-49c1-8466-acf32618a6d2"})

    assert a.authentication_mode is None
    assert a.is_authenticated() is False


def test_user_claims_shortcut():
    a = User(
        {"id": "001", "name": "Charlie Brown", "email": "charlie.brown@peanuts.eu"}
    )

    assert a.id == "001"
    assert a.name == "Charlie Brown"
    assert a.email == "charlie.brown@peanuts.eu"


def test_has_claim():
    a = Identity({"oid": "bc5f60df-4c27-49c1-8466-acf32618a6d2"})

    assert a.has_claim("oid")
    assert a.has_claim("foo") is False


def test_identity_dictionary_notation():
    a = Identity({"oid": "bc5f60df-4c27-49c1-8466-acf32618a6d2"})

    assert a["oid"] == "bc5f60df-4c27-49c1-8466-acf32618a6d2"

    with raises(KeyError):
        a["foo"]


def test_identity_sub():
    a = Identity({"sub": "bc5f60df-4c27-49c1-8466-acf32618a6d2"})

    assert a.sub == "bc5f60df-4c27-49c1-8466-acf32618a6d2"


def test_user_identity_dictionary_notation():
    a = User({"oid": "bc5f60df-4c27-49c1-8466-acf32618a6d2"})

    assert a["oid"] == "bc5f60df-4c27-49c1-8466-acf32618a6d2"

    with raises(KeyError):
        a["foo"]


def test_has_claim_value():
    a = Identity({"hello": "world", "foo": "foo"})

    assert a.has_claim_value("foo", "foo")
    assert a.has_claim_value("hello", "world")
    assert a.has_claim_value("hello", "World") is False


def test_claims_default():
    a = Identity()

    assert a.claims.get("oid") is None


@pytest.mark.asyncio
async def test_authentication_strategy():
    class ExampleHandler(AuthenticationHandler):
        async def authenticate(self, context: Request):
            # NB: imagine a web request with headers, and we authenticate the user
            # by parsing and validating a JWT token
            user = User({"id": context.headers["user"]})
            context.user = user
            return user

    strategy = AuthenticationStrategy(ExampleHandler())

    request = Request({"user": "xxx"})

    await strategy.authenticate(request)

    assert isinstance(request.user, User)
    assert request.user["id"] == "xxx"


@pytest.mark.asyncio
async def test_strategy_throws_for_missing_context():

    strategy = AuthenticationStrategy()

    with raises(ValueError):
        await strategy.authenticate(None)


class MockHandler(AuthenticationHandler):
    def __init__(self, identity):
        self.identity = identity

    async def authenticate(self, context: Any) -> Optional[Identity]:
        context.user = self.identity
        return context.user


class OneScheme(MockHandler):
    @property
    def scheme(self) -> str:
        return "one"


class TwoScheme(MockHandler):
    @property
    def scheme(self) -> str:
        return "two"


class ThreeScheme(MockHandler):
    @property
    def scheme(self) -> str:
        return "three"


def get_strategy_with_schemes():
    return AuthenticationStrategy(
        OneScheme(User({"id": "001", "scope": "A"})),
        TwoScheme(User({"id": "001", "scope": "B"})),
        ThreeScheme(User({"id": "001", "scope": "C"})),
    )


@pytest.mark.asyncio
async def test_authentication_strategy_by_scheme():
    strategy = get_strategy_with_schemes()

    request = Request({})

    await strategy.authenticate(request, ["three"])

    assert isinstance(request.user, User)
    assert request.user["scope"] == "C"


@pytest.mark.asyncio
async def test_authentication_strategy_by_scheme_throws_for_missing_scheme():
    strategy = get_strategy_with_schemes()

    with raises(AuthenticationSchemesNotFound):
        await strategy.authenticate(Request({}), ["four"])


def test_default_authentication_scheme_name_matches_class_name():
    class Basic(AuthenticationHandler):
        async def authenticate(self, context: Any) -> Optional[Identity]:
            pass

    class Foo(AuthenticationHandler):
        async def authenticate(self, context: Any) -> Optional[Identity]:
            pass

    assert Basic().scheme == "Basic"
    assert Foo().scheme == "Foo"


class Foo:
    pass


class InjectedAuthenticationHandler(AuthenticationHandler):
    service: Foo

    def authenticate(self, context) -> Optional[Identity]:
        return None


@pytest.mark.asyncio
async def test_authentication_di():
    container = Container()

    container.register(Foo)
    container.register(InjectedAuthenticationHandler)  # TODO: auto register?

    auth = AuthenticationStrategy(InjectedAuthenticationHandler, container=container)

    result = await auth.authenticate("example")
    assert result is None


@pytest.mark.asyncio
async def test_authenticate_set_identity_context_attribute_error_handling():
    """
    Tests that trying to set the identity on a context that does not support setting
    attributes does not cause an exception.
    """
    test_id = uuid4()
    container = Container()

    class TestHandler(AuthenticationHandler):
        def authenticate(self, context: Any) -> Optional[Identity]:
            return Identity({"sub": test_id})

    container.register(TestHandler)

    auth = AuthenticationStrategy(TestHandler, container=container)

    class A:
        __slots__ = ("x",)

    context = A()

    result = await auth.authenticate(context)
    assert isinstance(result, Identity)
    assert result.sub == test_id
