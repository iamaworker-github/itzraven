from typing import Dict, Any, Optional, Type, TypeVar, Generic, Callable
from contextvars import ContextVar

from itzraven.core.logger import get_logger

logger = get_logger()

T = TypeVar("T")


class ServiceNotFoundError(Exception):
    pass


class ServiceAlreadyRegisteredError(Exception):
    pass


class ServiceLifecycle:
    SINGLETON = "singleton"
    TRANSIENT = "transient"
    SCOPED = "scoped"


class ServiceRegistration(Generic[T]):
    def __init__(
        self,
        factory: Callable[..., T],
        lifecycle: str = ServiceLifecycle.SINGLETON,
        instance: Optional[T] = None,
    ):
        self.factory = factory
        self.lifecycle = lifecycle
        self._instance = instance

    def get_instance(self, container: "DIContainer") -> T:
        if self.lifecycle == ServiceLifecycle.SINGLETON:
            if self._instance is None:
                self._instance = self.factory(container)
            return self._instance
        elif self.lifecycle == ServiceLifecycle.SCOPED:
            scope = container.current_scope
            if scope is None:
                return self.factory(container)
            if self._name not in scope:
                scope[self._name] = self.factory(container)
            return scope[self._name]
        return self.factory(container)


_current_scope: ContextVar[Optional[Dict[str, Any]]] = ContextVar("di_scope", default=None)


class DIContainer:
    _instance: Optional["DIContainer"] = None

    def __init__(self):
        self._services: Dict[str, ServiceRegistration] = {}
        self._aliases: Dict[str, str] = {}

    def register(
        self,
        name: str,
        factory: Callable[..., T],
        lifecycle: str = ServiceLifecycle.SINGLETON,
        alias: Optional[str] = None,
    ) -> None:
        if name in self._services:
            raise ServiceAlreadyRegisteredError(f"Service '{name}' already registered")
        reg = ServiceRegistration(factory, lifecycle)
        reg._name = name
        self._services[name] = reg
        if alias:
            self._aliases[alias] = name

    def register_instance(self, name: str, instance: Any, alias: Optional[str] = None) -> None:
        if name in self._services:
            raise ServiceAlreadyRegisteredError(f"Service '{name}' already registered")
        reg = ServiceRegistration(lambda c: instance, ServiceLifecycle.SINGLETON)
        reg._instance = instance
        reg._name = name
        self._services[name] = reg
        if alias:
            self._aliases[alias] = name

    def resolve(self, name: str) -> Any:
        resolved_name = self._aliases.get(name, name)
        reg = self._services.get(resolved_name)
        if reg is None:
            raise ServiceNotFoundError(f"Service '{name}' not found")
        try:
            return reg.get_instance(self)
        except Exception as e:
            logger.error(f"Failed to resolve service '{name}': {e}")
            raise

    def get(self, name: str, default: Any = None) -> Any:
        try:
            return self.resolve(name)
        except ServiceNotFoundError:
            return default

    def has(self, name: str) -> bool:
        return name in self._services or name in self._aliases

    def remove(self, name: str) -> None:
        self._services.pop(name, None)
        self._aliases = {k: v for k, v in self._aliases.items() if v != name}

    def clear(self):
        self._services.clear()
        self._aliases.clear()

    @property
    def current_scope(self) -> Optional[Dict[str, Any]]:
        return _current_scope.get()

    def enter_scope(self) -> Dict[str, Any]:
        scope: Dict[str, Any] = {}
        _current_scope.set(scope)
        return scope

    def exit_scope(self):
        _current_scope.set(None)

    @classmethod
    def get_instance(cls) -> "DIContainer":
        if cls._instance is None:
            cls._instance = DIContainer()
        return cls._instance


_container: Optional[DIContainer] = None


def get_container() -> DIContainer:
    global _container
    if _container is None:
        _container = DIContainer()
    return _container
