import abc
from enum import Enum, auto
from typing import Dict, Type, Optional, TypeVar

from ipsiblings.model import SiblingCandidate, TimestampSeries


class SiblingProperty(metaclass=abc.ABCMeta):
    @classmethod
    @abc.abstractmethod
    def provide_for(cls, evaluated_sibling: 'EvaluatedSibling') -> Optional['SiblingProperty']:
        """Returns a new instance for given EvaluatedSibling. Raises if dynamic provision is not supported."""
        raise NotImplementedError


class SiblingStatus(Enum):
    POSITIVE = auto()
    NEGATIVE = auto()
    INDECISIVE = auto()
    ERROR = auto()


class SiblingClassification(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_result(self) -> SiblingStatus:
        raise NotImplementedError


PT = TypeVar('PT', bound=SiblingProperty)


class EvaluatedSibling:
    def __init__(self, candidate: SiblingCandidate):
        self._candidate = candidate  # TODO: Do we need this?
        self.series = {4: candidate.series4, 6: candidate.series6}
        self._properties: Dict[Type[SiblingProperty], SiblingProperty] = {}
        self.classifications: Dict[Type[SiblingClassification], SiblingClassification] = {}

    def get_property(self, property_type: Type[PT]) -> PT:
        return self._properties[property_type]

    def contribute_property_type(self, property_type: Type[PT]) -> PT:
        """
        Contributes a property of given type.
        That is, if already present, return the property of given type.
        Otherwise, dynamically provide an instance via the type's provide_for class method.
        Note that dynamic provision is not supported for all types.
        """
        if property_type in self._properties:
            return self.get_property(property_type)
        created = property_type.provide_for(self)
        self.put_property(created)
        return created

    def put_property(self, new_property: SiblingProperty):
        self._properties[type(new_property)] = new_property

    def __getitem__(self, item) -> TimestampSeries:
        if item == 4:
            return self.series[4]
        elif item == 6:
            return self.series[6]
        else:
            raise KeyError
