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

    @abstractmethod
    async def handle(self, context: AuthorizationContext):
        """Handles this requirement for a given context."""


class AuthorizationStrategy:

    __slots__ = ('policies',
                 'identity_getter')

    def __init__(self,
                 identity_getter: Callable[[Dict], Identity],
                 *policies: Policy
                 ):
        self.policies = policies
        self.identity_getter = identity_getter

    def get_policy(self, name: str) -> Optional[Policy]:
        for policy in self.policies:
            if policy.name == name:
                return policy
        return None

    async def handle(self, policy_name: Optional[str], arguments: Dict):
        identity = self.identity_getter(arguments)

        if policy_name:
            policy = self.get_policy(policy_name)

            if not policy:
                raise PolicyNotFoundError(policy_name)

            with AuthorizationContext(identity, policy.requirements) as context:

                for requirement in policy.requirements:
                    if isinstance(requirement, SyncRequirement):
                        requirement.handle(context)
                    else:
                        await requirement.handle(context)

                if not context.succeeded:
                    raise UnauthorizedError(context.forced_failure,
                                            context.pending_requirements)
        else:
            if not identity:
                raise UnauthorizedError('Missing identity', [])
            if not identity.is_authenticated():
                raise UnauthorizedError('The resource requires authentication', [])

    def __call__(self, policy: Optional[str] = None):
        def decorator(fn):
            args_getter = args_to_dict_getter(fn)

            @wraps(fn)
            async def wrapper(*args, **kwargs):
                await self.handle(policy, args_getter(args, kwargs))
                return await fn(*args, **kwargs)

            return wrapper
        return decorator
