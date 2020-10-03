from typing import List


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
