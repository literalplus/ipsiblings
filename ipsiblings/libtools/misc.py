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


def split_list(l, n):
    """
    Splits list l into chunks of size n. Returns a generator.
    """
    # https://stackoverflow.com/a/312464
    for i in range(0, len(l), n):
        yield l[i:i + n]
