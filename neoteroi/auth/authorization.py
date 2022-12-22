import inspect
from abc import ABC, abstractmethod
from functools import wraps
from typing import Callable, Dict, Iterable, List, Optional, Sequence

from neoteroi.auth.authentication import Identity
from neoteroi.auth.funchelper import args_to_dict_getter


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
    def handle(self, context: "AuthorizationContext"):
        """Handles this requirement for a given context."""


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
        self._succeeded = set()
        self._failed_forced = None

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
        return self._failed_forced

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
        self._failed_forced = False
        self._succeeded.clear()


class Policy:

    __slots__ = ("name", "requirements")

    def __init__(self, name: str, *requirements: Requirement):
        self.name = name
        self.requirements = list(requirements) or []

    def add(self, requirement: Requirement) -> "Policy":
        self.requirements.append(requirement)
        return self

    def __iadd__(self, other: Requirement):
        if not isinstance(other, Requirement):
            raise ValueError("Only requirements can be added using __iadd__ syntax")
        self.requirements.append(other)
        return self

    def __repr__(self):
        return f'<Policy "{self.name}" at {id(self)}>'


class BaseAuthorizationStrategy(ABC):
    def __init__(
        self,
        *policies: Policy,
        default_policy: Optional[Policy] = None,
        identity_getter: Optional[Callable[[Dict], Identity]] = None,
    ):
        self.policies = list(policies)
        self.default_policy = default_policy
        self.identity_getter = identity_getter

    def get_policy(self, name: str) -> Optional[Policy]:
        for policy in self.policies:
            if policy.name == name:
                return policy
        return None

    def add(self, policy: Policy) -> "BaseAuthorizationStrategy":
        self.policies.append(policy)
        return self

    def __iadd__(self, policy: Policy) -> "BaseAuthorizationStrategy":
        self.policies.append(policy)
        return self

    def with_default_policy(self, policy: Policy) -> "BaseAuthorizationStrategy":
        self.default_policy = policy
        return self

    @abstractmethod
    async def authorize(self, policy_name: Optional[str], identity: Identity):
        """
        Applies authorization rules, raising an exception if the given identity is not
        authorized.
        """

    @abstractmethod
    def __call__(self, policy: Optional[str] = None):
        """
        Used to decorate a function to apply authorization checks on call.

        TODO: document
        """


class AuthorizationStrategy(BaseAuthorizationStrategy):
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
                raise UnauthorizedError("Missing identity", [])
            if not identity.is_authenticated():
                raise UnauthorizedError("The resource requires authentication", [])

    def _get_requirements(self, policy: Policy) -> Iterable[Requirement]:
        ###
        # TODO: instantiate requirements here! To support DI.
        ###
        for requirement in policy.requirements:
            if isinstance(requirement, Requirement):
                yield requirement

    async def _handle_with_policy(self, policy: Policy, identity: Identity):
        with AuthorizationContext(identity, policy.requirements) as context:

            for requirement in self._get_requirements(policy):
                if inspect.iscoroutinefunction(requirement.handle):
                    await requirement.handle(context)
                else:
                    requirement.handle(context)

            if not context.has_succeeded:
                raise UnauthorizedError(
                    context.forced_failure, context.pending_requirements
                )

    async def _handle_with_identity_getter(
        self, policy_name: Optional[str], arguments: Dict
    ):
        if self.identity_getter is None:
            raise TypeError("Missing identity getter function.")
        await self.authorize(policy_name, self.identity_getter(arguments))

    def __call__(self, policy: Optional[str] = None):
        def decorator(fn):
            args_getter = args_to_dict_getter(fn)

            @wraps(fn)
            async def wrapper(*args, **kwargs):
                await self._handle_with_identity_getter(
                    policy, args_getter(args, kwargs)
                )
                return await fn(*args, **kwargs)

            return wrapper

        return decorator
