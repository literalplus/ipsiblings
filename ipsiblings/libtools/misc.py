# misc.py
#
# (c) 2018 Marco Starke
#

import collections


def is_iterable(obj):
    """
    Considers only non-string types as iterables
    """
    return isinstance(obj, collections.Iterable) and not isinstance(obj, str)
