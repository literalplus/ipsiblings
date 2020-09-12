# libts/candidatepair.py
#
# (c) 2018 Marco Starke
#


"""
This module provides functions to retrieve remote timestamps.
"""

from .. import libconstants as const
from .. import liblog

log = liblog.get_root_logger()


class CandidatePair(object):

    def __init__(
            self, ip4, ip6,
            ports4=None, ports6=None,
            tcp4_opts=None, tcp6_opts=None,
            ip4_ts=None, ip6_ts=None,
            domains=set()
    ):
        """
        CandidatePair objects are based on IP addresses which means they may have multiple domains assigned.
        For example, google uses very often 172.217.18.14 / 2a00:1450:4001:80b::200e
        but also companies acquired by google (e.g. zynamics.com)
        """
        self.ip4 = ip4
        self.ip6 = ip6
        self.ports4 = ports4 if ports4 else set()
        self.ports6 = ports6 if ports6 else set()
        self.tcp4_opts = tcp4_opts
        self.tcp6_opts = tcp6_opts
        self.ip4_ts = ip4_ts if ip4_ts else {}  # { port: [ (remote_ts, received_ts) ] }
        self.ip6_ts = ip6_ts if ip6_ts else {}
        self.domains = domains if type(domains) is set else set(domains)

        if ports4 and ports6:
            self.is_responsive4 = True
            self.is_responsive6 = True
        elif ports4 and not ports6:
            self.is_responsive4 = True
            self.is_responsive6 = False
        elif not ports4 and ports6:
            self.is_responsive4 = False
            self.is_responsive6 = True
        else:
            self.is_responsive4 = False
            self.is_responsive6 = False

    def add_domain(self, domain):
        self.domains.add(domain)

    def add_ts_record(self, ip, port, remote_ts, received_ts, tcp_options, ipversion):
        if ipversion == const.IP_VERSION_4:
            tsdata = self.ip4_ts
        else:  # hopefully 6
            tsdata = self.ip6_ts

        if port in tsdata:
            tsdata[port].append((remote_ts, received_ts))
        else:
            tsdata[port] = [(remote_ts, received_ts)]

    def assign_portscan_record(self, port, tcp_opts, ipversion):
        self.add_port(port, ipversion)
        self.set_tcp_options(tcp_opts, ipversion)

    def add_port(self, port, ipversion):
        if ipversion == const.IP_VERSION_4:
            self.ports4.add(port)
            self.is_responsive4 = True
        elif ipversion == const.IP_VERSION_6:
            self.ports6.add(port)
            self.is_responsive6 = True
        else:
            raise ValueError("IP version can only be 4 or 6!")

    def set_ports4(self, ports):
        if ports:
            self.is_responsive4 = True
        else:
            log.debug('Assigned ports empty for {0}'.format(self.ip4))
        self.ports4 = ports

    def set_ports6(self, ports):
        if ports:
            self.is_responsive6 = True
        else:
            log.debug('Assigned ports empty for {0}'.format(self.ip6))
        self.ports6 = ports

    def set_tcp_options(self, options, ipversion):
        if ipversion == const.IP_VERSION_4:
            if not self.tcp4_opts:
                self.tcp4_opts = options
        elif ipversion == const.IP_VERSION_6:
            if not self.tcp6_opts:
                self.tcp6_opts = options
        else:
            raise ValueError("IP version can only be 4 or 6!")

    def get_ips(self):
        return self.ip4, self.ip6

    def get_ports(self):
        return self.ports4, self.ports6

    def get_timestamps(self):
        return self.ip4_ts, self.ip6_ts

    def get_tcp_options(self):
        return self.tcp4_opts, self.tcp6_opts

    def get_domains(self):
        return self.domains

    def is_responsive(self):
        return self.is_responsive4 and self.is_responsive6

    def is_active(self):
        return self.is_responsive()
