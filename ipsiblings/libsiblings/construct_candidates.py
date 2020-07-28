# libsiblings/construct_candidates.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

import itertools

from .siblingcandidate import SiblingCandidate
from .lowrtsiblingcandidate import LowRTSiblingCandidate
from .. import libconstants as const
from .. import liblog

log = liblog.get_root_logger()


def construct_node_candidates(candidate_pairs, all_ports_timestamps=False, low_runtime=False, nr_timestamps=None):
    """
    Constructs a dictionary structured as shown below.
    Per default, the lowest common port (if multiple ports are available) is used to construct the
    sibling candidate. In case of no ports in common, the lowest of each IP is used.

    all_ports_timestamps    construct candidates for each port combination (cartesian product) [default: False]
    low_runtime             use LowRTSiblingCandidate class

    Returns:
    -> { ip4_port4_ip6_port6: SiblingCandidate }
    """
    if not candidate_pairs:
        return {}

    candidates = {}

    if not any([cp.is_responsive() for cp in candidate_pairs.values()]):
        log.warning('No timestamp data available! Candidate pairs need harvesting first!')
        return candidates

    for cp in candidate_pairs.values():
        if not cp.is_responsive():
            continue

        if all_ports_timestamps:
            if nr_timestamps:
                scs = from_CandidatePair(cp, all_ports=True, low_runtime=True, nr_timestamps=nr_timestamps)
            else:
                scs = from_CandidatePair(cp, all_ports=True, low_runtime=low_runtime)
            candidates = {**candidates, **scs}
        else:
            if nr_timestamps:
                key, sc = from_CandidatePair(cp, all_ports=False, low_runtime=True, nr_timestamps=nr_timestamps)
            else:
                key, sc = from_CandidatePair(cp, all_ports=False, low_runtime=low_runtime)

            if not key or not sc:  # faulty candidate pair provided
                continue
            candidates[key] = sc

    return candidates


def construct_trace_candidates(trace_sets, all_ports_timestamps=False, low_runtime=False, add_traces=False):
    """
    Constructs a dictionary structured as shown below.
    Uses the port index which offers the most timestamps.

    all_ports_timestamps    construct candidates for each port combination (cartesian product) [default: False]
    low_runtime             use LowRTSiblingCandidate class

    Returns:
    -> { ip4_port4_ip6_port6: SiblingCandidate }
    """
    if not trace_sets:
        return {}

    candidates = {}

    # check if any trace set has timestamp data available
    if not any([ts.has_timestamp_data() for ts in trace_sets.values()]):
        log.warning('No timestamp data available! Trace sets need harvesting first!')
        return candidates

    for trace_set in trace_sets.values():
        if not trace_set.has_timestamp_data():
            continue

        v4nodes, v6nodes = trace_set.get_active_nodes()
        candidates_ips = itertools.product(v4nodes.keys(), v6nodes.keys())  # [ (ip4, ip6) ]
        td4 = trace_set.get_trace_data()[4]  # { ip: { port: [ (remote_ts, received_ts) ] } }
        td6 = trace_set.get_trace_data()[6]
        tcp_options = trace_set.get_tcp_options()
        trace_set_id = trace_set.id()

        if add_traces:
            trace_data = (
            [trace.get_trace_lists() for trace in trace_set.get_traces().values()], trace_set.get_target())
        else:
            trace_data = None

        # for each responding node in this trace set
        for cand_ip4, cand_ip6 in candidates_ips:
            # tcp options
            if tcp_options:
                opt4 = tcp_options.get(cand_ip4)
                opt6 = tcp_options.get(cand_ip6)
            else:
                opt4, opt6 = None, None
            # timestamps
            port_ts4 = td4.get(cand_ip4)
            port_ts6 = td6.get(cand_ip6)

            if not port_ts4 or not port_ts6:  # if no timestamps available for this ip continue
                log.info('[{0}] {1} / {2} - Not enough timestamp data available ... skipping ...'.format(trace_set_id,
                                                                                                         cand_ip4,
                                                                                                         cand_ip6))
                continue

            ports4 = list(port_ts4.keys())
            ports6 = list(port_ts6.keys())
            has_ssh = const.SSH_PORT in ports4 and const.SSH_PORT in ports6

            if all_ports_timestamps:
                ports = itertools.product(ports4, ports6)
                # for each responding port of the current IPs
                for port4, port6 in ports:
                    key = '{0}_{1}_{2}_{3}'.format(cand_ip4, port4, cand_ip6, port6)
                    if key in candidates:  # no need to recreate SiblingCnadidate object
                        continue

                    if low_runtime:
                        siblingcandidate = LowRTSiblingCandidate(cand_ip4, cand_ip6, port4, port6, port_ts4[port4],
                                                                 port_ts6[port6], opt4, opt6, ssh_available=has_ssh,
                                                                 trace_set_id=trace_set_id, trace_data=trace_data)
                    else:
                        siblingcandidate = SiblingCandidate(cand_ip4, cand_ip6, port4, port6, port_ts4[port4],
                                                            port_ts6[port6], opt4, opt6, ssh_available=has_ssh,
                                                            trace_set_id=trace_set_id, trace_data=trace_data)
                    candidates[key] = siblingcandidate

            else:
                # use port which delivers the maximum number of timestamps
                port_index4, timestamps4 = max(port_ts4.items(), key=lambda x: len(x[1]))
                port_index6, timestamps6 = max(port_ts6.items(), key=lambda x: len(x[1]))
                # default branch -> use the lowest common port or the lowest of v4/v6 timestamps
                # intersecting_ports = set(port_ts4.keys()).intersection(set(port_ts6.keys()))
                # if not intersecting_ports: # no common ports
                #   # choose the lowest port
                #   port_index4, port_index6 = sorted(port_ts4.keys())[0], sorted(port_ts6.keys())[0]
                #   timestamps4, timestamps6 = port_ts4[port_index4], port_ts6[port_index6]
                # else:
                #   port_index = sorted(intersecting_ports)[0] # take the lowest port in common
                #   timestamps4, timestamps6 = port_ts4[port_index], port_ts6[port_index]
                #   port_index4 = port_index6 = port_index

                key = '{0}_{1}_{2}_{3}'.format(cand_ip4, port_index4, cand_ip6, port_index6)
                if key in candidates:  # no need to recreate SiblingCnadidate object
                    continue

                if low_runtime:
                    siblingcandidate = LowRTSiblingCandidate(cand_ip4, cand_ip6, port_index4, port_index6, timestamps4,
                                                             timestamps6, opt4, opt6, ssh_available=has_ssh,
                                                             trace_set_id=trace_set_id, trace_data=trace_data)
                else:
                    siblingcandidate = SiblingCandidate(cand_ip4, cand_ip6, port_index4, port_index6, timestamps4,
                                                        timestamps6, opt4, opt6, ssh_available=has_ssh,
                                                        trace_set_id=trace_set_id, trace_data=trace_data)
                candidates[key] = siblingcandidate

    return candidates


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
        # intersecting_ports = set(ports4).intersection(set(ports6))
        # if not intersecting_ports:
        #   p4, p6 = sorted(ports4)[0], sorted(ports6)[0]
        #   timestamps4, timestamps6 = ts4[p4], ts6[p6]
        # else:
        #   common_port = sorted(intersecting_ports)[0]
        #   timestamps4, timestamps6 = ts4[common_port], ts6[common_port]
        #   p4, p6 = common_port, common_port

        key = '{0}_{1}_{2}_{3}'.format(ip4, p4, ip6, p6)
        if low_runtime:
            sc = LowRTSiblingCandidate(ip4, ip6, p4, p6, timestamps4, timestamps6, opts4, opts6, domains=domains,
                                       ssh_available=has_ssh, nr_timestamps=nr_timestamps)
        else:
            sc = SiblingCandidate(ip4, ip6, p4, p6, timestamps4, timestamps6, opts4, opts6, domains=domains,
                                  ssh_available=has_ssh)

        return key, sc
