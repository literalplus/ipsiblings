# sentinel.py
#
# (c) 2018 Marco Starke
#

import collections

"""
Sentinel collections that keep track of whether they have been modified or not.
"""


class SentinelList(collections.UserList):
    # This class shows how attributes of parent classes can be hidden from
    # subclasses by using '__getattribute__' and '__dir__' functions.
    # -> https://medium.com/@maouu/sorry-but-youre-wrong-aea1b88ffc03
    # unclear: why is this done?
    def __getattribute__(self, name):
        excluded = ['__mul__', '__imul__', '__rmul__', 'copy', 'pop']
        if name in excluded:
            raise NotImplementedError(name)
        else:
            return super().__getattribute__(name)

    def __dir__(self):
        excluded = ['__mul__', '__imul__', '__rmul__', 'copy', 'pop']
        return sorted((set(dir(self.__class__)) | set(self.__dict__.keys())) - set(excluded))

    def __init__(self, *args, **kwargs):
        """
        Extends collections.UserList and adds a sentinel member.
        """
        super().__init__(*args, **kwargs)
        self.__modified = False

    @property
    def modified(self):
        return self.__modified

    def reset_modified(self):
        """
        Set current data state to initial state (modification is tracked from now on)
        """
        self.__modified = False

    def __setitem__(self, i, item):
        super().__setitem__(i, item)
        self.__modified = True

    def __delitem__(self, i):
        super().__delitem__(i)
        self.__modified = True

    def __add__(self, other):
        instance = super().__add__(other)
        self.__modified = True
        return instance

    def __radd__(self, other):
        instance = super().__radd__(other)
        self.__modified = True
        return instance

    def __iadd__(self, other):
        instance = super().__iadd__(other)
        self.__modified = True
        return instance

    def append(self, item):
        super().append(item)
        self.__modified = True

    def insert(self, i, item):
        super().insert(i, item)
        self.__modified = True

    # def pop(self, i = -1): # excluded to show how attributes can be removed from subclasses
    #   val = super().pop(i)
    #   self.__modified = True
    #   return val

    def remove(self, item):
        super().remove(item)
        self.__modified = True

    def clear(self):
        super().clear()
        self.__modified = True

    # def copy(self): # excluded to show how attributes can be removed from subclasses
    #   return super().copy()

    def reverse(self):
        super().reverse()
        self.__modified = True

    def sort(self, *args, **kwargs):
        super().sort(*args, **kwargs)
        self.__modified = True

    def extend(self, other):
        super().extend(other)
        self.__modified = True


class SentinelDict(collections.UserDict):

    def __init__(self, *args, **kwargs):
        """
        Extends collections.UserDict and adds a modified boolean property.
        If __delitem__ or __setitem__ are called, modified is set to True.
        Be aware that other modification methods do not track at the moment!
        """
        super().__init__(*args, **kwargs)
        self.__modified = False

    def get(self, key):
        return self.__getitem__(key)

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.__modified = True

    def set(self, key, value):
        self.__setitem__(key, value)

    def __delitem__(self, key):
        super().__delitem__(key)
        self.__modified = True

    @property
    def modified(self):
        return self.__modified

    def reset_modified(self):
        """
        Set current data state to initial state (modification is tracked from now on)
        """
        self.__modified = False
