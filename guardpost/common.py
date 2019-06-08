from .authorization import Policy
from .synchronous.authorization import Requirement, AuthorizationContext


class NoopRequirement(Requirement):

    def handle(self, context: AuthorizationContext):
        context.succeed(self)


class NoopPolicy(Policy):

    def __init__(self, name: str = 'anyone'):
        super().__init__(name, NoopRequirement())


class AnonymousRequirement(Requirement):

    def handle(self, context: AuthorizationContext):
        identity = context.identity

        if not identity or not identity.is_authenticated():
            context.succeed(self)


class AnonymousPolicy(Policy):

    def __init__(self, name: str = 'anonymous'):
        super().__init__(name, AnonymousRequirement())
