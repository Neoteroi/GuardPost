from functools import wraps
from typing import Sequence, Optional, Union, Mapping as MappingType, Callable, Dict
from collections.abc import Mapping
from abc import abstractmethod
from guardpost.authentication import Identity
from guardpost.funchelper import args_to_dict_getter
from guardpost.authorization import (AuthorizationContext,
                                     Policy,
                                     BaseRequirement,
                                     PolicyNotFoundError,
                                     UnauthorizedError)


class Requirement(BaseRequirement):
    """Base class for synchronous authorization requirements."""

    @abstractmethod
    def handle(self, context: AuthorizationContext):
        """Handles this requirement for a given context"""


RequiredClaimsType = Union[MappingType[str, str], Sequence[str], str]


class ClaimsRequirement(Requirement):

    __slots__ = ('required_claims',)

    def __init__(self, required_claims: RequiredClaimsType):
        if isinstance(required_claims, str):
            required_claims = [required_claims]
        self.required_claims = required_claims

    def handle(self, context: AuthorizationContext):
        identity = context.identity

        if not identity:
            context.fail('Missing identity')
            return

        if isinstance(self.required_claims, Mapping):
            if all(identity.has_claim_value(key, value) for key, value in self.required_claims.items()):
                context.succeed(self)
        else:
            if all(identity.has_claim(name) for name in self.required_claims):
                context.succeed(self)


class AuthenticatedRequirement(Requirement):

    def handle(self, context: AuthorizationContext):
        identity = context.identity

        if identity and identity.is_authenticated():
            context.succeed(self)


class AuthorizationStrategy:

    __slots__ = ('policies',
                 'identity_getter',
                 'default_policy')

    def __init__(self,
                 identity_getter: Callable[[Dict], Identity],
                 *policies: Policy
                 ):
        self.policies = policies
        self.identity_getter = identity_getter
        self.default_policy = None  # type: Optional[Policy]

    def get_policy(self, name: str) -> Optional[Policy]:
        for policy in self.policies:
            if policy.name == name:
                return policy
        return None

    def handle(self, policy_name: Optional[str], arguments: Dict):
        self.authorize(policy_name, self.identity_getter(arguments))

    @staticmethod
    def _handle_with_policy(policy: Policy, identity: Identity):
        with AuthorizationContext(identity, policy.requirements) as context:

            for requirement in policy.requirements:
                requirement.handle(context)

            if not context.succeeded:
                raise UnauthorizedError(context.forced_failure,
                                        context.pending_requirements)

    def authorize(self, policy_name: Optional[str], identity: Identity):
        if policy_name:
            policy = self.get_policy(policy_name)

            if not policy:
                raise PolicyNotFoundError(policy_name)

            self._handle_with_policy(policy, identity)
        else:
            if self.default_policy:
                self._handle_with_policy(self.default_policy, identity)
                return

            if not identity:
                raise UnauthorizedError('Missing identity', [])
            if not identity.is_authenticated():
                raise UnauthorizedError('The resource requires authentication', [])

    def __call__(self, policy: Optional[str] = None):
        def decorator(fn):
            args_getter = args_to_dict_getter(fn)

            @wraps(fn)
            def wrapper(*args, **kwargs):
                self.handle(policy, args_getter(args, kwargs))
                return fn(*args, **kwargs)

            return wrapper
        return decorator
