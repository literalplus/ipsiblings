from typing import Dict, Type, Optional, TypeVar, List, Iterator

from ipsiblings.evaluation.model.exportregistry import ExportRegistry
from ipsiblings.evaluation.model.property import SiblingProperty, SiblingPropertyException
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.model import SiblingCandidate, TimestampSeries, const

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

    def property_failed(self, property_type: Type[PT]) -> bool:
        return self.has_property(property_type) and self.get_property(property_type) is None

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
        return SiblingStatus.combine(self.classifications.values())


ExportRegistry.register_root_key('domains')
ExportRegistry.register_root_key('status')
for ipv in (4, 6):
    ExportRegistry.register_root_key(f'ip{ipv}')
    ExportRegistry.register_root_key(f'port{ipv}')
    ExportRegistry.register_root_key(f'tcpopts{ipv}')
for choice in const.EvaluatorChoice:
    ExportRegistry.register_root_key(f'status_{choice.name}')
