# libts/tracepair.py
#
# (c) 2018 Marco Starke
#


class TracePair(object):
    def __init__(self, ip4, ip6, domain=None):
        """
        Holds IP and domain information.
        """
        self.ip4 = ip4
        self.ip6 = ip6
        self.domain = domain
