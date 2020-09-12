# libsiblings/construct_candidates.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

import itertools
from typing import Dict

from .lowrtsiblingcandidate import LowRTSiblingCandidate
from .siblingcandidate import SiblingCandidate
from .. import libconstants as const
from .. import liblog
from ..bootstrap.exception import ConfigurationException
from ..config import AppConfig
from ..preparation import PreparedPairs, PreparedTargets

log = liblog.get_root_logger()


def _construct_pair_candidates(
        prepared_pairs: PreparedPairs, low_runtime=False, nr_timestamps=None
) -> Dict[str, SiblingCandidate]:
    """
    Constructs a dictionary structured as shown below.
    Per default, the lowest common port (if multiple ports are available) is used to construct the
    sibling candidate. In case of no ports in common, the lowest of each IP is used.

    low_runtime             use LowRTSiblingCandidate class

    Returns:
    -> { ip4_port4_ip6_port6: SiblingCandidate }
    """
    candidate_pairs = prepared_pairs.candidate_pairs
    if not candidate_pairs:
        return {}

    candidates = {}

    if not any([cp.is_responsive() for cp in candidate_pairs.values()]):
        log.warning('No timestamp data available! Candidate pairs need harvesting first!')
        return candidates

    for cp in candidate_pairs.values():
        if not cp.is_responsive():
            continue
        if nr_timestamps:
            key, sc = from_CandidatePair(cp, all_ports=False, low_runtime=True, nr_timestamps=nr_timestamps)
        else:
            key, sc = from_CandidatePair(cp, all_ports=False, low_runtime=low_runtime)

        if not key or not sc:  # faulty candidate pair provided
            continue
        candidates[key] = sc
    return candidates


def construct_candidates_for(prepared_targets: PreparedTargets, conf: AppConfig) -> Dict[str, SiblingCandidate]:
    if isinstance(prepared_targets, PreparedPairs):
        return _construct_pair_candidates(prepared_targets, low_runtime=conf.candidates.low_runtime)
    else:
        raise ConfigurationException(
            f'Unable to construct candidates for targets of kind {prepared_targets.get_kind()}'
        )


################################################################################
################################################################################

def from_CandidatePair(cp, all_ports=False, low_runtime=False, nr_timestamps=None):
    """
    Returns a SiblingCandidate object or a list of such if all_ports is True.
    key = ip4_port4_ip6_port6
    -> (key, SiblingCandidate) or { key: SiblingCandidate }
    """
    ip4, ip6 = cp.get_ips()
    ts4, ts6 = cp.get_timestamps()

    # ports4, ports6 = cp.get_ports()
    # not for all ports are probably timestamps available
    # cp.get_ports() != (ts4.keys(), ts6.keys())
    # -> to be sure use the dict keys of the timestamp data
    ports4, ports6 = list(ts4.keys()), list(ts6.keys())
    # based on this experience, we must check if there is timestamp data available at all
    invalid_candidate = False
    if len(ports4) < 1:
        # log.warning('[{0}] / {1} ({2} - {3}) - No timestamp data available!'.format(ip4, ip6, getattr(cp, 'domains', 'None'), cp.get_ports()))
        invalid_candidate = True

    if len(ports6) < 1:
        # log.warning('{0} / [{1}] ({2} - {3}) - No timestamp data available!'.format(ip4, ip6, getattr(cp, 'domains', 'None'), cp.get_ports()))
        invalid_candidate = True

    if invalid_candidate:  # if there is no data available we must ignore this candidate
        if all_ports:
            return {}
        else:
            return (None, None)

    opts4, opts6 = cp.get_tcp_options()
    domains = cp.get_domains()

    has_ssh = const.SSH_PORT in ports4 and const.SSH_PORT in ports6

    if all_ports:
        candidates = {}
        ports = itertools.product(ports4, ports6)
        for p4, p6 in ports:
            key = '{0}_{1}_{2}_{3}'.format(ip4, p4, ip6, p6)
            if low_runtime:
                sc = LowRTSiblingCandidate(ip4, ip6, p4, p6, ts4[p4], ts6[p6], opts4, opts6, domains=domains,
                                           ssh_available=has_ssh, nr_timestamps=nr_timestamps)
            else:
                sc = SiblingCandidate(ip4, ip6, p4, p6, ts4[p4], ts6[p6], opts4, opts6, domains=domains,
                                      ssh_available=has_ssh)
            candidates[key] = sc

        return candidates

    else:
        # use port which delivers the maximum number of timestamps
        p4, timestamps4 = max(ts4.items(), key=lambda x: len(x[1]))
        p6, timestamps6 = max(ts6.items(), key=lambda x: len(x[1]))

        key = '{0}_{1}_{2}_{3}'.format(ip4, p4, ip6, p6)
        if low_runtime:
            sc = LowRTSiblingCandidate(
                ip4, ip6, p4, p6, timestamps4, timestamps6, opts4, opts6,
                domains=domains, ssh_available=has_ssh, nr_timestamps=nr_timestamps
            )
        else:
            sc = SiblingCandidate(
                ip4, ip6, p4, p6, timestamps4, timestamps6, opts4, opts6,
                domains=domains, ssh_available=has_ssh
            )

        return key, sc
