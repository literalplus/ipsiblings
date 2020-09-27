import abc
from enum import Enum, auto
from typing import Dict, Type, Optional, TypeVar, Generic, List, Any, Tuple, Iterator, Set

from ipsiblings import libtools
from ipsiblings.model import SiblingCandidate, TimestampSeries, BusinessException, const


class ExportRegistry:
    _REGISTERED_KEYS = set()

    @classmethod
    def register_root_key(cls, key):
        cls._REGISTERED_KEYS.add(key)

    @classmethod
    def register_keys(cls, property_type):
        for key in property_type.get_export_keys():
            cls.register_root_key(property_type.prefix_key(key))

    @classmethod
    def get_header_fields(cls) -> List[str]:
        lst = list(cls._REGISTERED_KEYS)
        lst.sort()
        return lst


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


class SiblingStatus(Enum):
    POSITIVE = auto()
    NEGATIVE = auto()
    INDECISIVE = auto()
    CONFLICT = auto()
    ERROR = auto()


# State machine, nodes represent current overall status, edges represent a classification with that status.
# No edge means no change, None value means always override the current status
_STATUS_TRANSITIONS = {
    SiblingStatus.POSITIVE: {SiblingStatus.NEGATIVE: SiblingStatus.CONFLICT},
    SiblingStatus.NEGATIVE: {SiblingStatus.POSITIVE: SiblingStatus.CONFLICT},
    SiblingStatus.INDECISIVE: None,
    SiblingStatus.ERROR: {SiblingStatus.POSITIVE: SiblingStatus.POSITIVE,
                          SiblingStatus.NEGATIVE: SiblingStatus.NEGATIVE},
}


class SiblingPropertyException(BusinessException):
    def __init__(self, message: str, cause: Optional[Exception] = None):
        super(SiblingPropertyException, self).__init__(message)
        if cause:
            self.__cause__ = cause


PT = TypeVar('PT', bound=SiblingProperty)


class EvaluatedSibling:
    def __init__(self, candidate: SiblingCandidate):
        self.key = candidate.key
        self.series = candidate.series
        self.domains = candidate.domains
        self.tcp_options = candidate.tcp_options

        self._properties: Dict[Type[SiblingProperty], Optional[SiblingProperty]] = {}
        self.classifications: Dict[const.EvaluatorChoice, SiblingStatus] = {}
        self.property_errors: List[SiblingPropertyException] = []

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        if isinstance(other, EvaluatedSibling):
            return self.key == other.key
        return NotImplemented

    def __str__(self):
        return 'EvaluatedSibling -> ' + \
               "<>".join([str(s.key) for s in self.series.values()]) + \
               f' -> {self.classifications}'

    def __getitem__(self, item) -> TimestampSeries:
        if item == 4:
            return self.series[4]
        elif item == 6:
            return self.series[6]
        else:
            raise KeyError

    def __iter__(self) -> Iterator[TimestampSeries]:
        yield self[4]
        yield self[6]

    def get_property(self, property_type: Type[PT]) -> Optional[PT]:
        return self._properties[property_type]

    def has_property(self, property_type: Type[PT]) -> bool:
        return self._properties.get(property_type) is not None

    def contribute_property_type(self, property_type: Type[PT]) -> Optional[PT]:
        """
        Contributes a property of given type.
        That is, if already present, return the property of given type.
        Otherwise, dynamically provide an instance via the type's provide_for class method.
        Note that dynamic provision is not supported for all types.
        """
        if property_type in self._properties:
            return self.get_property(property_type)
        try:
            created = property_type.provide_for(self)
        except Exception as e:
            self.property_errors.append(SiblingPropertyException(
                f'Failed to compute property {property_type.__name__}', e
            ))
            raise
        if created is not None:
            self.put_property(created)
        else:
            self._properties[property_type] = None
        return created

    def put_property(self, new_property: SiblingProperty):
        self._properties[type(new_property)] = new_property

    def export(self) -> Dict[str, str]:
        exported = {
            'domains': const.SECONDARY_DELIMITER.join(self.domains),
            'status': self.overall_status.name,
        }
        for series in self:
            ip_version = series.ip_version
            exported[f'ip{ip_version}'] = series.target_ip
            exported[f'port{ip_version}'] = str(series.target_port)
            exported[f'tcpopts{ip_version}'] = str(self.tcp_options[ip_version]) \
                if self.tcp_options[ip_version] else const.NONE_MARKER
        for prop in self._properties.values():
            if prop is None:
                continue
            for key, value in prop.export().items():
                exported[type(prop).prefix_key(key)] = str(value)
        for key, status in self.classifications.items():
            exported[f'status_{key.name}'] = status.name
        return exported

    @property
    def overall_status(self) -> SiblingStatus:
        overall = SiblingStatus.INDECISIVE
        for key, status in self.classifications.items():
            transitions = _STATUS_TRANSITIONS[overall]
            if not transitions:
                overall = status
            else:
                next_overall = transitions.get(status)
                if next_overall:
                    overall = next_overall
        return overall


ExportRegistry.register_root_key('domains')
ExportRegistry.register_root_key('status')
for ipv in (4, 6):
    ExportRegistry.register_root_key(f'ip{ipv}')
    ExportRegistry.register_root_key(f'port{ipv}')
    ExportRegistry.register_root_key(f'tcpopts{ipv}')
for choice in const.EvaluatorChoice:
    ExportRegistry.register_root_key(f'status_{choice.name}')
