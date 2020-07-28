# cdnfilter.py
#
# (c) 2019 Marco Starke
#


"""
Filter CDNs by providing a file containing CDN IP address ranges.
"""

import ipaddress
import pathlib

from . import libconstants as const
from . import liblog
from . import libtools

log = liblog.get_root_logger()


class CDNFilter(object):

    def __init__(self, filename):

        self.filename = filename
        self.ip4cdns = []
        self.ip6cdns = []
        invalid = []

        with open(filename, mode='r') as filterfile:
            for line in filterfile:
                line = line.strip().lower()
                if not line or line.startswith('#'):
                    continue

                try:
                    ipnet = ipaddress.ip_network(line)
                except ValueError:
                    invalid.append(line)
                    continue

                if type(ipnet) == ipaddress.IPv4Network:
                    self.ip4cdns.append(ipnet)
                else:
                    self.ip6cdns.append(ipnet)

        if invalid:
            log.warning('Invalid networks: {0}'.format(', '.join(invalid)))

        if self.ip4cdns or self.ip6cdns:
            nr_cdns = len(self.ip4cdns) + len(self.ip6cdns)
            log.info('Loaded [{0}] CDN networks to filter'.format(nr_cdns))

    def is_cdn(self, ip4, ip6=None):
        if not ip6:
            addr = ipaddress.ip_address(ip4)
            if type(addr) == ipaddress.IPv4Address:
                for network in self.ip4cdns:
                    if addr in network:
                        return True
            else:
                for network in self.ip6cdns:
                    if addr in network:
                        return True
        else:
            addr6 = ipaddress.ip_address(ip6)  # probably less IPv6 networks
            for network in self.ip6cdns:
                if addr6 in network:
                    return True
            addr4 = ipaddress.ip_address(ip4)
            for network in self.ip4cdns:
                if addr4 in network:
                    return True

        return False

    def filter(self, candidate_tuples):
        """
        Filters a list of IP tuples based on CDN membership.
        Retruns (allowed, filtered, error)

        Format: [([domains], ip4, ip6)] or [(ip4, ip6)]
        """
        allowed = []
        filtered = []
        error = []

        for record in candidate_tuples:
            *domain, ip4, ip6 = record  # domain is [] if not available

            try:
                ip4 = ipaddress.ip_address(ip4)
                ip6 = ipaddress.ip_address(ip6)
            except ValueError:
                # log.warning('Could not parse [{0} / {1}] to a valid IP addresses'.format(str(ip4), str(ip6)))
                if domain:
                    try:
                        d, = domain  # if only one element in list -> extract it and add domain
                    except ValueError:
                        d = ','.join(domain)  # join them if there are more elements
                    error.append((d, ip4, ip6))
                else:
                    error.append((ip4, ip6))
                continue

            is_cdn = False
            for network in self.ip6cdns:  # number of IPv6 networks is probably smaller
                if ip6 in network:
                    is_cdn = True
                    break

            if not is_cdn:
                for network in self.ip4cdns:
                    if ip4 in network:
                        is_cdn = True
                        break

            if is_cdn:
                temp_list = filtered
            else:
                temp_list = allowed

            if domain:
                try:
                    d, = domain  # if only one element in list -> extract it and add domain
                except ValueError:
                    d = ','.join(domain)  # join them if there are more elements
                temp_list.append((d, ip4, ip6))
            else:
                temp_list.append((ip4, ip6))

        return allowed, filtered, error


def write_filtered(directory, data, include_domain=False):
    filename = pathlib.Path(directory) / const.CDN_FILTERED_FILENAME
    record_counter = 0
    with open(filename, mode='w') as outfile:
        if include_domain:
            for (ip4, ip6), domains in data.items():
                if libtools.is_iterable(domains):
                    domains = ','.join(domains)
                row = '{0};{1};{2}\n'.format(ip4, ip6, domains)
                outfile.write(row)
                record_counter = record_counter + 1
        else:
            for ip4, ip6 in data.keys():
                row = '{0};{1}\n'.format(ip4, ip6)
                outfile.write(row)
                record_counter = record_counter + 1

    return record_counter
