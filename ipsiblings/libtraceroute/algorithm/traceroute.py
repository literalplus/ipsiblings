# algorithms.traceroute.py
#
# (c) 2018 Marco Starke
#


import scapy.all as scapy

from ipsiblings import libconstants as const
from .base import Algorithm
from ..error import TracerouteException


class TracerouteAlgorithm(Algorithm):
    """
    This 'algorithm' uses the Scapy traceroute implementation.

    init():
    Parameters provided in the dictionary are passed to Scapy's traceroute function.

    protocol  - specify the used protocol for tracerouting [tcp]
    srcport   - set sourceport [random short]
    dstport   - set destination port [80]
    min_ttl   - set min ttl [1]
    max_ttl   - set max ttl [30]
    timeout   - set timeout in seconds [2]
    filter    - filter packets [None]
    verbose   - print output to stdout [None]
    l4        - provide own layer 4 crafted with scapy [None]

    Based on 'protocol' parameter a scapy packet will be provided as 'l4' parameter.
    Either 'protocol' or 'l4' may be set. None of them will default to tcp traceroute.
    """

    def __init__(self):
        """
        This implementation does not use any constructor arguments.
        """
        pass

    def init(self, algorithm_params={}):
        # Traceroute 'constructor' parameters
        # protocol, srcport, dstport, min_ttl, max_ttl, timeout, detect_broken_nat
        # scapy parameters:
        # target, dport=80, minttl=1, maxttl=30, sport=RandShort(), l4=None, filter=None, timeout=2, verbose=None, **kargs
        self.params = algorithm_params

    def run(self):
        """
        Returns (trace, scapy.TracerouteResult)
        """

        trace = {}
        if const.TRACEROUTE_ADD_SOURCE_IP:
            # ownipv4, ownipv6 = libtools.get_iface_IPs(iface = self.params.iface)
            ownipv4, ownipv6 = const.IFACE_IP4_ADDRESS, const.IFACE_IP6_ADDRESS

        # scapy built-in: https://scapy.readthedocs.io/en/latest/usage.html#tcp-traceroute-2
        # can also specify own layer4 protocol by providing parameter 'l4'
        if self.params.ipversion is const.IP_VERSION_4:
            tr_res, unans = scapy.traceroute(str(self.params.ipaddress), maxttl=self.params.max_ttl, verbose=0)
            if const.TRACEROUTE_ADD_SOURCE_IP:
                trace[0] = ownipv4
        elif self.params.ipversion is const.IP_VERSION_6:
            tr_res, unans = scapy.traceroute6(str(self.params.ipaddress), maxttl=self.params.max_ttl, verbose=0)
            if const.TRACEROUTE_ADD_SOURCE_IP:
                trace[0] = ownipv6
        else:
            raise TracerouteException('Illegal IP version provided!')

        for k, v in tr_res.get_trace()[str(self.params.ipaddress)].items():
            if v[0] == str(self.params.ipaddress) and const.TRACEROUTE_WITHOUT_DESTINATION_IP:
                continue
            trace[k] = v[0]

        trace = dict(sorted(trace.items()))

        return trace, tr_res
