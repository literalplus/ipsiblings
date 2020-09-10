# fileio.py
#
# (c) 2018 Marco Starke
#

import csv
import errno
import ipaddress
import os
import re

from ipsiblings.libtools.misc import is_iterable
from .trie import Trie
from .. import liblog

log = liblog.get_root_logger()


def write_constructed_pairs(filename, data, include_domain=False):
    nr_records = 0
    with open(filename, mode='w') as outfile:
        if include_domain:
            for record in data:
                domains, ip4, ip6 = record
                if is_iterable(domains):
                    domains = ','.join(domains)
                outfile.write('{0};{1};{2}\n'.format(ip4, ip6, domains))
                nr_records = nr_records + 1
        else:
            for record in data:
                ip4, ip6 = record
                outfile.write('{0};{1}\n'.format(ip4, ip6))
                nr_records = nr_records + 1

    return nr_records


def create_directories(file_or_dir):
    """
    Create all underlying directories if they do not exist.
    Returns False on error (but None if the directory was created during call).
    If the directory already exists None is returned.
    True, if successfully created.
    """
    directory = os.path.dirname(file_or_dir)
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except OSError as e:  # race condition guard
            if e.errno != errno.EEXIST:
                log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
                return False
            else:  # directory was created during call
                return None
        else:
            return True
    else:
        return None


# Determines IPv4/IPv6 indices automatically with the ipaddress module
# Scheitle et al. 2017 format:
# host_name;asn;asn_v4;asn_v6;country_code;address_v4;address_v6
# https://stackoverflow.com/a/904085
def parsecsv(fname, delimiter=';', iponly=True, include_domain=False):
    """
    Parse csv file to a list: [ (IPv4, IPv6), (IPv4, IPv6), ... ]
    If include_domain is given, the domain must be always on first position in the file!

    If 'iponly' is False additional information is parsed:
    [ (IPv4, IPv6), remaining, data, as, list, items ]

    fname           file to parse
    delimiter       optional (';')
    iponly          optional (True) returns a list of tuples containing (IPv4, IPv6) pairs
    include_domain  optional (False) in combination with iponly returns (domain, IPv4, IPv6)
                    domain must be the first position in each row (index 0)
    """
    ip4index = None
    ip6index = None

    candidate_list = []
    with open(fname, newline='', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=delimiter)

        # to ignore the header we may have to inspect the 2nd row to identify indices
        for _ in range(2):
            if ip4index and ip6index:  # if no header is present this must be checked to not miss the first data row
                break  # no header present, we already identified both indices
            row = next(csvreader)
            # determine ip4 and ip6 column index in csv file
            for pos, item in enumerate(row):
                try:
                    ip = ipaddress.ip_address(item)
                    if ip.version == 4:
                        ip4index = pos
                    elif ip.version == 6:
                        ip6index = pos
                except:
                    pass

        if ip4index is None or ip6index is None:
            raise ValueError('Could not determine indices for IP addresses!')

        # add first entry manually
        # use ipaddress module to standardize IPv6 address strings
        ip4, ip6 = row[ip4index], str(ipaddress.ip_address(row[ip6index]))
        if iponly:
            if include_domain:  # must be always at index 0 in each row
                record = (row[0], ip4, ip6)
            else:
                record = (ip4, ip6)
        else:
            record = [row[i] for i, e in enumerate(row) if i not in [ip4index, ip6index]]
            record.insert(0, (ip4, ip6))

        candidate_list.append(record)

        for row in csvreader:
            # use ipaddress module to standardize IPv6 address strings
            ip4, ip6 = row[ip4index], str(ipaddress.ip_address(row[ip6index]))

            if iponly:
                if include_domain:  # must be always at index 0 in each row
                    record = (row[0], ip4, ip6)
                else:
                    record = (ip4, ip6)
            else:
                record = [row[i] for i, e in enumerate(row) if i not in [ip4index, ip6index]]
                record.insert(0, (ip4, ip6))

            candidate_list.append(record)

    return candidate_list
