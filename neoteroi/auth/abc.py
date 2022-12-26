from abc import ABC
from typing import Any, Iterable, List, Optional, Type, TypeVar, Union

from neoteroi.di import ContainerProtocol

T = TypeVar("T")


class StrategyConfigurationError(Exception):
    """Base class for all configuration errors related to auth strategies."""


class DINotConfiguredError(StrategyConfigurationError):
    def __init__(self) -> None:
        super().__init__(
            "A DI Container is required for this strategy because it needs to activate "
            "types."
        )


class BaseStrategy(ABC):
    def __init__(self, container: Optional[ContainerProtocol] = None) -> None:
        super().__init__()
        self._container = container

    @property
    def container(self) -> ContainerProtocol:
        if self._container is None:
            raise DINotConfiguredError()
        return self._container

    @container.setter
    def container(self, container: ContainerProtocol) -> None:
        self._container = container

    def _get_di_scope(self, scope: Any):
        try:
            return scope._di_scope
        except AttributeError:
            return None

    def _get_instances(self, items: List[Union[T, Type[T]]], scope: Any) -> Iterable[T]:
        """
        Yields instances of types, optionally activated through dependency injection.

        If the given context has a DI scope defined in "_di_scope" attribute, it is
        used to support scoped services.
        """
        scope = self._get_di_scope(scope)
        for obj in items:
            if isinstance(obj, type):
                # a container is required
                yield self.container.resolve(obj, scope=scope)
            else:
                yield obj
