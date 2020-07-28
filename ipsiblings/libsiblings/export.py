# libsiblings/export.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

import csv

from .. import liblog

log = liblog.get_root_logger()


def prepare_tcp_opts(tcpopts, delimiter='-'):
    if tcpopts:
        out = []
        for k, v in tcpopts:  # list of tuples (name, value)
            if k == 'WScale':
                out.append('WS{0:0>2}'.format(v))
            elif k == 'Timestamp':
                out.append('TS')
            else:
                out.append(k)

        return delimiter.join(out)
    else:
        return ''


def prepare_domains(domains, delimiter=','):
    if domains:
        return delimiter.join(domains)
    else:
        return ''


def write_results(candidates, resultfile, low_runtime=False, delimiter=';'):
    """
    Write available results to resultfile
    """
    if low_runtime:
        keys = ['ip4', 'ip6', 'port4', 'port6', 'domains', 'hz4', 'hz6', 'hz4_R2', 'hz6_R2', 'raw_ts_diff',
                'ip4_tcpopts', 'ip6_tcpopts', 'ssh_keys_match', 'ssh_agents_match', 'geo4', 'geo6', 'geoloc_diff',
                'status', 'is_sibling']
    else:
        keys = ['ip4', 'ip6', 'port4', 'port6', 'domains', 'hz4', 'hz6', 'hz4_R2', 'hz6_R2', 'raw_ts_diff', 'alpha4',
                'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'theta', 'dynrange4', 'dynrange6', 'dynrange_diff',
                'dynrange_diff_rel', 'spl_percent_val', 'ip4_tcpopts', 'ip6_tcpopts', 'ssh_keys_match',
                'ssh_agents_match', 'geo4', 'geo6', 'geoloc_diff', 'status', 'is_sibling']

    linecounter = 0
    with open(resultfile, mode='w', newline='') as csvfile:
        csvout = csv.writer(csvfile, delimiter=delimiter)
        csvout.writerow(keys)  # write header
        for candidate in candidates:
            res = candidate.get_results()
            line = []
            for key in keys:
                if key == 'domains':
                    line.append(prepare_domains(res[key]))
                elif key == 'ip4_tcpopts' or key == 'ip6_tcpopts':
                    line.append(prepare_tcp_opts(res[key]))
                else:
                    line.append(res[key])

            csvout.writerow(line)
            linecounter = linecounter + 1

    return linecounter
