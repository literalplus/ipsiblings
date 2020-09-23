# misc.py
#
# (c) 2018 Marco Starke
#

import collections
import re


def is_iterable(obj):
    """
    Considers only non-string types as iterables
    """
    return isinstance(obj, collections.Iterable) and not isinstance(obj, str)


def camel_to_snake_case(camel_name: str) -> str:
    return re.sub(r'(?<!^)(?=[A-Z])', '_', camel_name).lower()
