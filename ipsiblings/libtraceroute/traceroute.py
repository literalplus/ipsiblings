# libtraceroute/traceroute.py
#
# (c) 2018 Marco Starke
#
#
# Traceroute module to traceroute target hosts.
# Option to simulate Paris-Traceroute/Dublin-Traceroute (Multipath Detection Algorithm, MDA)
#
# https://paris-traceroute.net
# https://hal.inria.fr/hal-01097558/file/e2emon2007.pdf
# https://hal.inria.fr/hal-01097562/document
#
# https://dublin-traceroute.net


import ipaddress

from .error import TracerouteException
from .algorithm.all import get_algorithm
from .. import libconstants as const
from .. import libtools


class Traceroute(object):
    """
    Takes a hostname or an IP (v4/v6) address as traceroute destination.
    Works with ipaddress.IPv{4,6}Address class.

    Use 'ipversion' parameter to explicitly use IPv4 or IPv6 if hostname
    instead of IP address was provided (e.g. ipversion = libconstants.IP_VERSION_6)

    [Planned for Paris-/Dublin-Traceroute usage towards algorithm implementations]
    """

    def __init__(
            self, target, iface='en0', algorithm='traceroute', protocol='tcp',
            srcport=const.TR_TCP_DEFAULT_SRC_PORT, dstport=const.TR_TCP_DEFAULT_DST_PORT,
            min_ttl=0, max_ttl=30, timeout=30, detect_broken_nat=False, ipversion=const.IP_VERSION_4
    ):

        libtools.validate((type(target) in [str, ipaddress.IPv4Address, ipaddress.IPv6Address]),
                          'Wrong type for [target], should be a string (hostname / IP address) [was \'{0}\']'.format(
                              type(target)))
        libtools.validate((type(ipversion) is int and ipversion in [const.IP_VERSION_4, const.IP_VERSION_6]),
                          'Illegal input, [ipversion] must be \'libconstants.IP_VERSION_4\' or \'libconstants.IP_Version_6\' [was \'{0}\']'.format(
                              type(ipversion)))

        # parse string to IP address (v4/v6)
        address = libtools.get_IP_from_str(target, ipversion)
        if not address:
            raise TracerouteException(
                'Input error, target is no IP address and no valid hostname. Could not resolve [{0}] to an IPv{1} address!'.format(
                    target, ipversion))

        if not libtools.crosscheck_ip_version(address, ipversion):
            raise TracerouteException('Given IP address does not match given IP version!')

        self.ipaddress = address
        self.ipversion = ipversion
        self.iface = iface

        self.algorithm_str = algorithm
        self.protocol = protocol
        self.srcport = srcport
        self.dstport = dstport
        self.min_ttl = min_ttl
        self.max_ttl = max_ttl
        self.timeout = timeout
        # this parameter may be used in future algorithm implementations (dublin-traceroute)
        self.detect_broken_nat = detect_broken_nat

        # scapy parameters
        self.filter = None
        self.retry = 0
        self.multi = False
        self.store_unanswered = False

        # Initialize traceroute algorithm
        self.algorithm = get_algorithm(algorithm)
        self.algorithm.init(algorithm_params=self)

    def start_trace(self):
        return self.algorithm.run()

    def start_traceroute(self):
        return self.algorithm.run()
