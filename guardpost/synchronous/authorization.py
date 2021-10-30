from abc import abstractmethod
from functools import wraps
from typing import Dict, Optional

from guardpost.authentication import Identity
from guardpost.authorization import (
    AuthorizationContext,
    BaseAuthorizationStrategy,
    BaseRequirement,
    Policy,
    PolicyNotFoundError,
    UnauthorizedError,
)
from guardpost.funchelper import args_to_dict_getter


class Requirement(BaseRequirement):
    """Base class for synchronous authorization requirements."""

    @abstractmethod
    def handle(self, context: AuthorizationContext):
        """Handles this requirement for a given context"""


class AuthorizationStrategy(BaseAuthorizationStrategy):
    def _handle_with_identity_getter(self, policy_name: Optional[str], arguments: Dict):
        self.authorize(policy_name, self.identity_getter(arguments))

    @staticmethod
    def _handle_with_policy(policy: Policy, identity: Identity):
        with AuthorizationContext(identity, policy.requirements) as context:

            for requirement in policy.requirements:
                requirement.handle(context)

            if not context.has_succeeded:
                raise UnauthorizedError(
                    context.forced_failure, context.pending_requirements
                )

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
                raise UnauthorizedError("Missing identity", [])
            if not identity.is_authenticated():
                raise UnauthorizedError("The resource requires authentication", [])

    def __call__(self, policy: Optional[str] = None):
        def decorator(fn):
            args_getter = args_to_dict_getter(fn)

            @wraps(fn)
            def wrapper(*args, **kwargs):
                self._handle_with_identity_getter(policy, args_getter(args, kwargs))
                return fn(*args, **kwargs)

            return wrapper

        return decorator
