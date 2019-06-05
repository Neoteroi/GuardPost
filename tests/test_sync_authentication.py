from pytest import raises
from tests.examples import Request
from guardpost.authentication import User
from guardpost.synchronous.authentication import AuthenticationHandler, AuthenticationStrategy


def test_authentication_strategy():

    class ExampleHandler(AuthenticationHandler):

        def authenticate(self, context: Request):
            # NB: imagine a web request with headers, and we authenticate the user
            # by parsing and validating a JWT token
            user = User({'id': context.headers['user']})
            context.user = user
            return user

    strategy = AuthenticationStrategy(ExampleHandler())

    request = Request({
        'user': 'xxx'
    })

    strategy.authenticate(request)

    assert isinstance(request.user, User)
    assert request.user['id'] == 'xxx'


def test_strategy_throws_for_missing_context():

    strategy = AuthenticationStrategy()

    with raises(ValueError):
        strategy.authenticate(None)