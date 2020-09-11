import pathlib
import random
from typing import Dict

from ipsiblings import liblog, libtrace, libconstants, libtools
from ipsiblings.bootstrap import Wiring
from ipsiblings.preparation.preparedtargets import PreparedTraceSets
from ._util import _reduce_map, _reduce_list
from ..bootstrap.exception import ConfigurationException, JustExit
from ..libtrace import TraceSet
from ..libtraceroute.cptraceroute import CPTraceroute
from ..libts.portscan import TraceSetPortScan

log = liblog.get_root_logger()


def load_trace_sets(wiring: Wiring) -> PreparedTraceSets:
    conf = wiring.conf
    log.info(f'Loading trace sets from base directory {conf.base_dir}')
    trace_sets = libtrace.load_trace_sets(
        conf.base_dir, wiring.nic, conf.paths.base_dir_silent,
        skip_list=wiring.skip_list
    )
    trace_sets = _reduce_map(trace_sets, conf, 'TraceSets')
    return PreparedTraceSets(trace_sets)


def prepare_trace_sets(wiring: Wiring) -> PreparedTraceSets:
    conf = wiring.conf
    ipdata = _obtain_targets(wiring)
    if conf.candidates.just_write_pairs_to:
        _export_and_exit(conf, ipdata)
    ipdata = _reduce_list(ipdata, conf, 'targets (ipdata)')
    return _try_prepare(ipdata, wiring)


def _obtain_targets(wiring):
    conf = wiring.conf
    include_domain = conf.targetprovider.has_resolved
    if conf.targetprovider.has_resolved:
        ipdata = wiring.target_provider.provide_targets()
        # gives ~250k targets for 145k resolved hosts of Alexa Top List
        if not ipdata:
            if conf.targetprovider.resolved_ips_path:
                raise ConfigurationException(f'{conf.targetprovider.resolved_ips_path}: Empty CSV file!')
            else:
                raise ConfigurationException('Empty target array!')
    else:
        ipdata = libtools.parsecsv(conf.paths.target_csv, iponly=True, include_domain=include_domain)
        if not ipdata:
            raise ConfigurationException(f'{conf.paths.target_csv}: Empty CSV file!')
    log.info(f'Constructed {len(ipdata)} candidates')
    return ipdata


def _export_and_exit(conf, ipdata):
    include_domain = conf.targetprovider.has_resolved
    nr_records = libtools.write_constructed_pairs(
        pathlib.Path(conf.base_dir) / conf.candidates.just_write_pairs_to,
        ipdata,
        include_domain=include_domain
    )
    log.info('Wrote [{0}] IP candidate pairs to [{1}]'.format(nr_records, str(
        pathlib.Path(conf.base_dir) / conf.candidates.just_write_pairs_to)))
    log.info('Exiting now ...')
    raise JustExit


def _try_prepare(ipdata, wiring: Wiring) -> PreparedTraceSets:
    trace_sets: Dict[str, TraceSet] = {}
    silent_trace_sets = {}  # trace sets with non responding nodes
    # randomize target list
    random.shuffle(ipdata)
    try:
        _do_prepare(ipdata, silent_trace_sets, trace_sets, wiring)
    finally:
        ts_written = libtrace.write_trace_sets(wiring.conf.base_dir, trace_sets)
        if libconstants.WRITE_INACTIVE_TRACE_SET:
            ts_silent_written = libtrace.write_trace_sets(wiring.conf.paths.base_dir_silent, silent_trace_sets)
            if ts_written > 0 or ts_silent_written > 0:
                log.info(f'Active TraceSets written: {ts_written} / Inactive TraceSets written: {ts_silent_written}')
        else:
            if ts_written > 0:
                log.info(f'Active TraceSets written: {ts_written}')
    return PreparedTraceSets(trace_sets)


def _do_prepare(ipdata, silent_trace_sets, trace_sets, wiring):
    conf = wiring.conf
    const = libconstants
    ipdata_len = len(ipdata)
    include_domain = conf.targetprovider.has_resolved

    for n, target in enumerate(ipdata, start=1):

        if include_domain:
            domains, ip4, ip6 = target
            if libtools.is_iterable(domains):
                domains = ','.join(domains)
            info_str = '({0} of {1}) Processing target {2} / {3} [{4}]'.format(n, ipdata_len, ip4, ip6, domains)
        else:
            ip4, ip6 = target
            domains = None
            info_str = '({0} of {1}) Processing target {2} / {3}'.format(n, ipdata_len, ip4, ip6)

        log.info(info_str)

        trace_set = libtrace.TraceSet(target=(ip4, ip6), domain=domains)
        key = str(ip4) + '_' + str(ip6)
        if key in trace_sets:  # should never happen
            log.error('Target {0} / {1} already in trace sets!'.format(ip4, ip6))
            continue

        nr_current_traces = 0
        # if more than X traces have no active nodes continue with next target
        no_results_counter = 0
        # in case there are no new traces available to hit the requested number of traces
        no_new_trace_counter = 0

        # -> libconstants.TRACEROUTE_ADD_SOURCE_IP (False)
        ip4tracert, ip6tracert = CPTraceroute(
            (ip4, ip6), iface=wiring.nic.name, algorithm='traceroute', timeout=2
        ).traceroute(result_timeout=3)

        try:
            trace = libtrace.Trace().init(
                ip4, ip6,
                ip4tracert, ip6tracert,
                wiring.nic,
                skip_list=wiring.skip_list
            )
        except ValueError:
            trace = None

        if not trace or trace.id() in trace_set.get_traces():
            no_new_trace_counter = no_new_trace_counter + 1
            if trace:
                log.debug(
                    'Trace {0} (with target {1} / {2}) already in current trace set! [{3}. retry]'.format(
                        trace.id(), ip4, ip6, no_new_trace_counter))
            else:
                log.debug('No trace data available for target ({0} / {1})! [{2}. retry]'.format(
                    ip4, ip6, no_new_trace_counter
                ))

            if no_new_trace_counter >= const.MAX_TRIES_FOR_NEW_TRACE:
                break
            continue

        nodes4, nodes6 = trace.get_global_valid_IPs(
            apply_ignore_regex=bool(conf.paths.ip_ignores))  # only apply regex if ignore file was given

        tsports = TraceSetPortScan(nodes4, nodes6, wiring.nic, port_list=const.PORT_LIST).start()
        while not tsports.finished():
            tsports.process_results(timeout=1)
        tsports.process_results(timeout=2)
        tsports.stop()

        ip4results, ip6results = tsports.results()
        if not ip4results and not ip6results:
            no_results_counter = no_results_counter + 1
            nr_current_traces = nr_current_traces - 1  # do not increment if we have no active nodes
            if no_results_counter >= const.INACTIVE_RESULTS_PER_TRACE_SET:
                # if there were more than X empty results continue with the next target
                break

        trace.set_active_nodes((ip4results, ip6results))
        trace_set.add_trace(trace)
        nr_current_traces = nr_current_traces + 1

        if trace_set.has_candidates():
            trace_sets[key] = trace_set
        else:
            silent_trace_sets[key] = trace_set
