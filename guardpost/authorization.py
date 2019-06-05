from abc import ABC
from typing import Sequence, Optional, List
from guardpost.authentication import Identity


class AuthorizationError(Exception):
    pass


class AuthorizationConfigurationError(Exception):
    pass


class PolicyNotFoundError(AuthorizationConfigurationError, RuntimeError):

    def __init__(self, name: str):
        super().__init__(f'Cannot find policy with name {name}')


class BaseRequirement(ABC):
    """Base class for authorization requirements"""

    def __str__(self):
        return self.__class__.__name__


class UnauthorizedError(AuthorizationError):

    def __init__(self,
                 forced_failure: Optional[str],
                 failed_requirements: Sequence[BaseRequirement]):
        super().__init__(self._get_message(forced_failure, failed_requirements))
        self.failed = forced_failure
        self.failed_requirements = failed_requirements

    @staticmethod
    def _get_message(forced_failure, failed_requirements):
        if forced_failure:
            return f'The user is not authorized to perform the selected action. {forced_failure}.'

        if failed_requirements:
            return f'The user is not authorized to perform the selected action. ' \
                f'Failed requirements: {", ".join(str(requirement) for requirement in failed_requirements)}.'
        return 'Unauthorized'


class AuthorizationContext:

    __slots__ = ('identity',
                 'requirements',
                 '_succeeded',
                 '_failed_forced')

    def __init__(self,
                 identity: Identity,
                 requirements: Sequence[BaseRequirement]):
        self.identity = identity
        self.requirements = requirements
        self._succeeded = set()
        self._failed_forced = None

    @property
    def pending_requirements(self) -> List[BaseRequirement]:
        return [item for item in self.requirements if item not in self._succeeded]

    @property
    def succeeded(self) -> bool:
        if self._failed_forced:
            return False
        return all(requirement in self._succeeded for requirement in self.requirements)

    @property
    def forced_failure(self) -> Optional[str]:
        return self._failed_forced

    def fail(self, reason: str):
        """Called to indicate that this authorization context has failed.
        Forces failure, regardless of succeeded requirements."""
        self._failed_forced = reason or 'Authorization failed.'

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.clear()

    def succeed(self, requirement: BaseRequirement):
        self._succeeded.add(requirement)

    def clear(self):
        self._failed_forced = False
        self._succeeded.clear()


class Policy:

    __slots__ = ('name',
                 'requirements')

    def __init__(self, name: str, *requirements: BaseRequirement):
        self.name = name
        self.requirements = requirements or []

    def __repr__(self):
        return f'<Policy "{self.name}" at {id(self)}>'
