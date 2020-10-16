from collections import defaultdict
from typing import Dict, Tuple, TYPE_CHECKING, TypeVar, Type, Optional, Any

from ipsiblings.model import TimestampSeries

if TYPE_CHECKING:
    from ipsiblings.evaluation.model import SiblingProperty

PT = TypeVar('PT')


class TargetPropertyCache:
    """
    Caches properties on a per-target level such that series-specific computations
    (i.e. such that are independent of the opposite IP version's data)
    do not need to be repeated.
    """
    data: Dict[Tuple[int, str], Dict[Type['SiblingProperty'], Any]] = defaultdict(dict)

    @classmethod
    def put_if_absent(cls, key: TimestampSeries, property_type: Type[PT], value: Any):
        target_dict = cls.data[(key.ip_version, key.target_ip)]
        if property_type not in target_dict:
            target_dict[property_type] = value

    @classmethod
    def get(cls, key: TimestampSeries, property_type: Type[PT]) -> Optional[Any]:
        all_properties = cls.data[(key.ip_version, key.target_ip)]
        return all_properties.get(property_type)

    @classmethod
    def has(cls, key: TimestampSeries, property_type: Type[PT]) -> bool:
        all_properties = cls.data[(key.ip_version, key.target_ip)]
        return property_type in all_properties

    @classmethod
    def clear(cls):
        cls.data.clear()
