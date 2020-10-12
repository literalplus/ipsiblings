import abc
from typing import Set, Optional, Dict, Any, Generic, Iterator, Tuple, TypeVar, Type

from .exportregistry import ExportRegistry
from ... import libtools
from ...model import BusinessException


class _PropertyMeta(abc.ABCMeta):
    def __new__(mcs, name, bases, namespace):
        # noinspection PyTypeChecker
        cls: 'Type[SiblingProperty]' = super(_PropertyMeta, mcs).__new__(mcs, name, bases, namespace)
        ExportRegistry.register_keys(cls)
        return cls


class SiblingProperty(metaclass=_PropertyMeta):
    @classmethod
    @abc.abstractmethod
    def get_export_keys(cls) -> Set[str]:
        """Valid keys for the export method."""
        return set()

    # noinspection PyUnresolvedReferences
    @classmethod
    @abc.abstractmethod
    def provide_for(cls, evaluated_sibling: 'EvaluatedSibling') -> Optional['SiblingProperty']:
        """Returns a new instance for given EvaluatedSibling. Raises if dynamic provision is not supported."""
        raise NotImplementedError

    @abc.abstractmethod
    def export(self) -> Dict[str, Any]:
        """Exports this property's metrics. Values will be str'd. Keys must be in get_export_keys."""
        return {}

    @classmethod
    @abc.abstractmethod
    def is_cacheable(cls):
        raise NotImplementedError

    @classmethod
    def prefix_key(cls, key: str) -> str:
        prefix = libtools.camel_to_snake_case(cls.__name__.replace('Property', ''))
        return f'{prefix}_{key}'


RT = TypeVar('RT')


class FamilySpecificSiblingProperty(SiblingProperty, Generic[RT], metaclass=abc.ABCMeta):
    """
    Abstract base class for address-family-specific properties.
    Must set properties data4 and data6 of type RT in the constructor.
    Provides access to these two via self[4] and self[6].
    """

    # noinspection PyUnresolvedReferences
    def __getitem__(self, item) -> RT:
        if item == 4:
            return self.data4
        elif item == 6:
            return self.data6
        else:
            raise KeyError

    # noinspection PyUnresolvedReferences
    def __iter__(self) -> Iterator[Tuple[int, RT]]:
        if self.data4:
            yield 4, self.data4
        if self.data6:
            yield 6, self.data6


class SiblingPropertyException(BusinessException):
    def __init__(self, message: str, cause: Optional[Exception] = None):
        super(SiblingPropertyException, self).__init__(message)
        if cause:
            self.__cause__ = cause