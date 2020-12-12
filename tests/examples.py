from guardpost.authorization import AuthorizationContext
from guardpost.synchronous.authorization import Requirement


class Request:
    def __init__(self, headers, user=None):
        self.headers = headers
        self.user = user


class NoopRequirement(Requirement):
    def handle(self, context: AuthorizationContext):
        context.succeed(self)
