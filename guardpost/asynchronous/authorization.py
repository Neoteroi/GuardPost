from typing import Callable, Dict, Optional
from functools import wraps
from abc import abstractmethod
from guardpost.authentication import Identity
from guardpost.authorization import (Policy,
                                     PolicyNotFoundError,
                                     AuthorizationContext,
                                     UnauthorizedError,
                                     BaseRequirement)
from guardpost.funchelper import args_to_dict_getter
from guardpost.synchronous.authorization import Requirement as SyncRequirement


class AsyncRequirement(BaseRequirement):
    """Base class for asynchronous authorization requirements."""

    @abstractmethod
    async def handle(self, context: AuthorizationContext):
        """Handles this requirement for a given context."""


class AuthorizationStrategy:

    __slots__ = ('policies',
                 'identity_getter',
                 'default_policy')

    def __init__(self,
                 *policies: Policy,
                 default_policy: Optional[Policy] = None,
                 identity_getter: Optional[Callable[[Dict], Identity]] = None):
        self.policies = policies
        self.default_policy = default_policy
        self.identity_getter = identity_getter

    def get_policy(self, name: str) -> Optional[Policy]:
        for policy in self.policies:
            if policy.name == name:
                return policy
        return None

    async def _handle_with_identity_getter(self, policy_name: Optional[str], arguments: Dict):
        await self.authorize(policy_name, self.identity_getter(arguments))

    @staticmethod
    async def _handle_with_policy(policy: Policy, identity: Identity):
        with AuthorizationContext(identity, policy.requirements) as context:

            for requirement in policy.requirements:
                if isinstance(requirement, SyncRequirement):
                    requirement.handle(context)
                else:
                    await requirement.handle(context)

            if not context.succeeded:
                raise UnauthorizedError(context.forced_failure,
                                        context.pending_requirements)

    async def authorize(self, policy_name: Optional[str], identity: Identity):
        if policy_name:
            policy = self.get_policy(policy_name)

            if not policy:
                raise PolicyNotFoundError(policy_name)

            await self._handle_with_policy(policy, identity)
        else:
            if self.default_policy:
                await self._handle_with_policy(self.default_policy, identity)
                return

            if not identity:
                raise UnauthorizedError('Missing identity', [])
            if not identity.is_authenticated():
                raise UnauthorizedError('The resource requires authentication', [])

    def __call__(self, policy: Optional[str] = None):
        def decorator(fn):
            args_getter = args_to_dict_getter(fn)

            @wraps(fn)
            async def wrapper(*args, **kwargs):
                await self._handle_with_identity_getter(policy, args_getter(args, kwargs))
                return await fn(*args, **kwargs)

            return wrapper
        return decorator
