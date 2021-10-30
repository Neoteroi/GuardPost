from abc import ABC
from typing import Callable, Dict, List, Optional, Sequence

from guardpost.authentication import Identity


class AuthorizationError(Exception):
    pass


class AuthorizationConfigurationError(Exception):
    pass


class PolicyNotFoundError(AuthorizationConfigurationError, RuntimeError):
    def __init__(self, name: str):
        super().__init__(f"Cannot find policy with name {name}")


class BaseRequirement(ABC):
    """Base class for authorization requirements"""

    def __str__(self):
        return self.__class__.__name__


class UnauthorizedError(AuthorizationError):
    def __init__(
        self,
        forced_failure: Optional[str],
        failed_requirements: Sequence[BaseRequirement],
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

    def __init__(self, identity: Identity, requirements: Sequence[BaseRequirement]):
        self.identity = identity
        self.requirements = requirements
        self._succeeded = set()
        self._failed_forced = None

    @property
    def pending_requirements(self) -> List[BaseRequirement]:
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

    def succeed(self, requirement: BaseRequirement):
        """Marks the given requirement as succeeded for this authorization context."""
        self._succeeded.add(requirement)

    def clear(self):
        self._failed_forced = False
        self._succeeded.clear()


class Policy:

    __slots__ = ("name", "requirements")

    def __init__(self, name: str, *requirements: BaseRequirement):
        self.name = name
        self.requirements = list(requirements) or []

    def add(self, requirement: BaseRequirement) -> "Policy":
        self.requirements.append(requirement)
        return self

    def __iadd__(self, other: BaseRequirement):
        if not isinstance(other, BaseRequirement):
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
