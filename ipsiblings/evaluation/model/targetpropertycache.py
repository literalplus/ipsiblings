from typing import Dict, Tuple, List, TYPE_CHECKING, TypeVar, Type, Optional

if TYPE_CHECKING:
    from ipsiblings.evaluation.model import SiblingProperty

PT = TypeVar('PT')


class TargetPropertyCache:
    """
    Caches properties on a per-target level such that series-specific computations
    (i.e. such that are independent of the opposite IP version's data)
    do not need to be repeated.
    """
    data: Dict[Tuple[int, str], 'List[SiblingProperty]'] = {}

    @classmethod
    def put(cls, ip_version: int, ip_address: str, properties: 'List[SiblingProperty]'):
        key = ip_version, ip_address
        if key in cls.data:
            return
        result = [prop for prop in properties if prop.is_cacheable()]
        if result:
            cls.data[key] = result

    @classmethod
    def get(cls, ip_version: int, ip_address: str, property_type: Type[PT]) -> Optional[PT]:
        all_properties = cls.data.get((ip_version, ip_address), [])
        typed_properties = [prop for prop in all_properties if isinstance(prop, property_type)]
        return typed_properties[0] if typed_properties else None
