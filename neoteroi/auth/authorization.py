import inspect
from abc import ABC, abstractmethod
from functools import lru_cache, wraps
from typing import Any, Callable, Iterable, List, Optional, Sequence, Set, Type, Union

from neoteroi.di import ContainerProtocol

from neoteroi.auth.abc import BaseStrategy
from neoteroi.auth.authentication import Identity


class AuthorizationError(Exception):
    pass


class AuthorizationConfigurationError(Exception):
    pass


class PolicyNotFoundError(AuthorizationConfigurationError, RuntimeError):
    def __init__(self, name: str):
        super().__init__(f"Cannot find policy with name {name}")


class Requirement(ABC):
    """Base class for authorization requirements."""

    def __str__(self):
        return self.__class__.__name__

    @abstractmethod
    async def handle(self, context: "AuthorizationContext"):
        """Handles this requirement for a given context."""


RequirementConfType = Union[Requirement, Type[Requirement]]


@lru_cache(maxsize=None)
def _is_async_handler(handler_type: Type[Requirement]) -> bool:
    # Faster alternative to using inspect.iscoroutinefunction without caching
    # Note: this must be used on Types - not instances!
    return inspect.iscoroutinefunction(handler_type.handle)


class UnauthorizedError(AuthorizationError):
    def __init__(
        self,
        forced_failure: Optional[str],
        failed_requirements: Sequence[Requirement],
        scheme: Optional[str] = None,
        error: Optional[str] = None,
        error_description: Optional[str] = None,
    ):
        """
        Creates a new instance of UnauthorizedError, with details.

        :param forced_failure: if applicable, the reason for a forced failure.
        :param failed_requirements: a sequence of requirements that failed.
        :param scheme: optional authentication scheme that should be used.
        :param error: optional error short text.
        :param error_description: optional error details.
        """
        super().__init__(self._get_message(forced_failure, failed_requirements))
        self.failed = forced_failure
        self.failed_requirements = failed_requirements
        self.scheme = scheme
        self.error = error
        self.error_description = error_description

    @staticmethod
    def _get_message(forced_failure, failed_requirements):
        if forced_failure:
            return (
                "The user is not authorized to perform the selected action."
                + f" {forced_failure}."
            )

        if failed_requirements:
            errors = ", ".join(str(requirement) for requirement in failed_requirements)
            return (
                f"The user is not authorized to perform the selected action. "
                f"Failed requirements: {errors}."
            )
        return "Unauthorized"


class AuthorizationContext:

    __slots__ = ("identity", "requirements", "_succeeded", "_failed_forced")

    def __init__(self, identity: Identity, requirements: Sequence[Requirement]):
        self.identity = identity
        self.requirements = requirements
        self._succeeded: Set[Requirement] = set()
        self._failed_forced: Optional[str] = None

    @property
    def pending_requirements(self) -> List[Requirement]:
        return [item for item in self.requirements if item not in self._succeeded]

    @property
    def has_succeeded(self) -> bool:
        if self._failed_forced:
            return False
        return all(requirement in self._succeeded for requirement in self.requirements)

    @property
    def forced_failure(self) -> Optional[str]:
        return None if self._failed_forced is None else str(self._failed_forced)

    def fail(self, reason: str):
        """
        Called to indicate that this authorization context has failed.
        Forces failure, regardless of succeeded requirements.
        """
        self._failed_forced = reason or "Authorization failed."

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()

    def succeed(self, requirement: Requirement):
        """Marks the given requirement as succeeded for this authorization context."""
        self._succeeded.add(requirement)

    def clear(self):
        self._failed_forced = None
        self._succeeded.clear()


class Policy:
    """
    Represents an authorization policy, with a set of authorization rules.
    """

    __slots__ = ("name", "requirements")

    def __init__(self, name: str, *requirements: RequirementConfType):
        self.name = name
        self.requirements = list(requirements) or []

    def _valid_requirement(self, obj):
        if not isinstance(obj, Requirement) or (
            isinstance(obj, type) and not issubclass(obj, Requirement)
        ):
            raise ValueError(
                "Only instances, or types, of Requirement can be added to the policy."
            )

    def add(self, requirement: RequirementConfType) -> "Policy":
        self._valid_requirement(requirement)
        self.requirements.append(requirement)
        return self

    def __iadd__(self, other: RequirementConfType):
        self._valid_requirement(other)
        self.requirements.append(other)
        return self

    def __repr__(self):
        return f'<Policy "{self.name}" at {id(self)}>'


class AuthorizationStrategy(BaseStrategy):
    def __init__(
        self,
        *policies: Policy,
        container: Optional[ContainerProtocol] = None,
        default_policy: Optional[Policy] = None,
        identity_getter: Optional[Callable[..., Identity]] = None,
    ):
        super().__init__(container)
        self.policies = list(policies)
        self.default_policy = default_policy
        self.identity_getter = identity_getter

    def get_policy(self, name: str) -> Optional[Policy]:
        for policy in self.policies:
            if policy.name == name:
                return policy
        return None

    def add(self, policy: Policy) -> "AuthorizationStrategy":
        self.policies.append(policy)
        return self

    def __iadd__(self, policy: Policy) -> "AuthorizationStrategy":
        self.policies.append(policy)
        return self

    def with_default_policy(self, policy: Policy) -> "AuthorizationStrategy":
        self.default_policy = policy
        return self

    async def authorize(
        self, policy_name: Optional[str], identity: Identity, scope: Any = None
    ):
        if policy_name:
            policy = self.get_policy(policy_name)

            if not policy:
                raise PolicyNotFoundError(policy_name)

            await self._handle_with_policy(policy, identity, scope)
        else:
            if self.default_policy:
                await self._handle_with_policy(self.default_policy, identity, scope)
                return

            if not identity:
                raise UnauthorizedError("Missing identity", [])
            if not identity.is_authenticated():
                raise UnauthorizedError("The resource requires authentication", [])

    def _get_requirements(self, policy: Policy, scope: Any) -> Iterable[Requirement]:
        yield from self._get_instances(policy.requirements, scope)

    async def _handle_with_policy(self, policy: Policy, identity: Identity, scope: Any):
        with AuthorizationContext(
            identity, list(self._get_requirements(policy, scope))
        ) as context:

            for requirement in context.requirements:
                if _is_async_handler(type(requirement)):  # type: ignore
                    await requirement.handle(context)
                else:
                    requirement.handle(context)  # type: ignore

            if not context.has_succeeded:
                raise UnauthorizedError(
                    context.forced_failure, context.pending_requirements
                )

    async def _handle_with_identity_getter(
        self, policy_name: Optional[str], *args, **kwargs
    ):
        if self.identity_getter is None:
            raise TypeError("Missing identity getter function.")
        await self.authorize(policy_name, self.identity_getter(*args, **kwargs))

    def __call__(self, policy: Optional[str] = None):
        """
        Decorates a function to apply authorization logic on each call.
        """

        def decorator(fn):
            @wraps(fn)
            async def wrapper(*args, **kwargs):
                await self._handle_with_identity_getter(policy, *args, **kwargs)
                return await fn(*args, **kwargs)

            return wrapper

        return decorator
