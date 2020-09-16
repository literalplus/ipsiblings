# fileio.py
#
# (c) 2018 Marco Starke
#

import errno
import os

from .misc import is_iterable
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
