#!/usr/bin/env python3
#
# main.py
#
# (c) 2018 Marco Starke
#

"""
Module main

This is the main module.

"""

import csv
import gc
import os
import pathlib
import random
import sys
import traceback

from ipsiblings.bootstrap.exception import ConfigurationException, JustExit, BusinessException, DataException
from ipsiblings.libts.harvester import TraceSetHarvester, CandidateHarvester
from ipsiblings.libts.portscan import TraceSetPortScan, CandidatePortScan
from ipsiblings.libts.serialization import load_candidate_pairs, write_candidate_pairs
from . import config, bootstrap, libconstants
from . import keyscan
from . import liblog
from . import libsiblings
from . import libtools
from . import libtrace
from . import settings
from .libtraceroute.cptraceroute import CPTraceroute

# setup root logger
log = liblog.setup_root_logger()
# set log level for scapy => disables warnings
liblog.set_scapy_loglevel(libconstants.LOG_LVL_SCAPY)
# set field_size_limit() from 131072 (2**17) to 262144 (2**18)
csv.field_size_limit(262144)


def _prepare_reduce(iterable, conf, what):
    should_reduce = (conf.start_index or conf.end_index)
    if not iterable or not should_reduce:
        return False
    inp_len = len(iterable)
    if conf.end_index is None or conf.end_index > inp_len:
        conf.end_index = inp_len
    if conf.start_index >= conf.end_index:
        log.error(f'{what} - Start index must be less than end index ({conf.start_index} to {conf.end_index})')
        sys.exit(-6)
    elif conf.start_index >= inp_len:
        log.error(f'{what} - Start index exceeds available input ({conf.start_index} >= {inp_len}')
        sys.exit(-6)
    else:
        return True


def _reduce_map(inp_dict, conf, what):
    # Python 3.6+ preserves insertion order with built-in dict
    if not _prepare_reduce(inp_dict, conf, what):
        return inp_dict
    original_len = len(inp_dict)
    keys = list(inp_dict.keys())[conf.start_index: conf.end_index]
    result = {key: inp_dict[key] for key in keys}
    log.info(f'Reduced loaded {what} from size [{original_len}] to [{len(result)}] '
             f'(indices [{conf.start_index}] to [{conf.end_index}])')
    return result


def _reduce_list(inp_list, conf, what):
    if not _prepare_reduce(inp_list, conf, what):
        return inp_list
    original_len = len(inp_list)
    result = inp_list[conf.start_index: conf.end_index]
    log.info(f'Reduced loaded {what} from size [{original_len}] to [{len(result)}] '
             f'(indices [{conf.start_index}] to [{conf.end_index}])')
    return result


def _validate_config(conf):
    if conf.targetprovider.resolved_ips_path and not conf.targetprovider.has_resolved:
        config.print_usage_and_exit('-f/--resolved-file can only be used with -s/--resolved')

    if conf.targetprovider.do_download and not conf.targetprovider.has_resolved:
        config.print_usage_and_exit('-o/--download-alexa can only be used with -s/--resolved')

    if conf.end_index is not None:
        if conf.start_index < 0 or conf.end_index < 1:
            config.print_usage_and_exit('--from/--to can not be negative/zero')
        if conf.start_index >= conf.end_index:
            config.print_usage_and_exit('--to can not be less or equal to --from')


def _bridge_config_to_legacy(conf: config.AppConfig, const: libconstants):
    log.setLevel(conf.log_level)
    const.BASE_DIRECTORY = conf.base_dir
    # PORT_LIST selection based on --router-ports/--server-ports options or operation mode (-c/-t)
    # prioritize the explicit arguments
    if conf.port_scan.router_portlist:
        const.PORT_LIST = const.PORT_LIST_ROUTER
    elif conf.port_scan.server_portlist:
        const.PORT_LIST = const.PORT_LIST_SERVER
    else:
        if conf.candidates.available:
            const.PORT_LIST = const.PORT_LIST_SERVER
        elif conf.flags.has_targets or conf.flags.load_tracesets:
            const.PORT_LIST = const.PORT_LIST_ROUTER
        else:
            const.PORT_LIST = const.PORT_LIST_SERVER


def handle_targets(trace_sets, wiring):
    conf = wiring.conf
    const = libconstants
    silent_trace_sets = {}  # trace sets with non responding nodes

    if conf.targetprovider.has_resolved:
        include_domain = True
        ipdata = wiring.target_provider.provide_targets()
        # gives ~250k targets for 145k resolved hosts of Alexa Top List
        if not ipdata:
            if conf.targetprovider.resolved_ips_path:
                raise ConfigurationException(f'{conf.targetprovider.resolved_ips_path}: Empty CSV file!')
            else:
                raise ConfigurationException('Empty target array!')
    else:
        include_domain = False
        ipdata = libtools.parsecsv(conf.paths.target_csv, iponly=True, include_domain=include_domain)
        if not ipdata:
            raise ConfigurationException(f'{conf.paths.target_csv}: Empty CSV file!')
    log.info(f'Constructed {len(ipdata)} candidates')
    if conf.candidates.just_write_pairs:
        nr_records = libtools.write_constructed_pairs(
            pathlib.Path(conf.base_dir) / conf.candidates.just_write_pairs,
            ipdata,
            include_domain=include_domain
        )
        log.info('Wrote [{0}] IP candidate pairs to [{1}]'.format(nr_records, str(
            pathlib.Path(conf.base_dir) / conf.candidates.just_write_pairs)))
        log.info('Exiting now ...')
        raise JustExit
    ipdata = _reduce_list(ipdata, conf, 'targets (ipdata)')
    # randomize target list
    random.shuffle(ipdata)
    ipdata_len = len(ipdata)
    try:
        ### TARGET LOOP ###
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

            while nr_current_traces < const.NR_TRACES_PER_TRACE_SET:
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
    finally:
        ts_written = libtrace.write_trace_sets(conf.base_dir, trace_sets)
        if const.WRITE_INACTIVE_TRACE_SET:
            ts_silent_written = libtrace.write_trace_sets(conf.paths.base_dir_silent, silent_trace_sets)
            if ts_written > 0 or ts_silent_written > 0:
                log.info('Active TraceSets written: {0} / Inactive TraceSets written: {1}'.format(ts_written,
                                                                                                  ts_silent_written))
        else:
            if ts_written > 0:
                log.info('Active TraceSets written: {0}'.format(ts_written))


def handle_candidates(conf, wiring):
    if conf.targetprovider.has_resolved:
        ports_available = False
        ts_data_available = False
        candidate_pairs = wiring.target_provider.provide_candidates()
        if not candidate_pairs:
            if conf.targetprovider.resolved_ips_path:
                raise DataException(
                    f'Target provider did not provide any candidate pairs '
                    f'from {conf.targetprovider.resolved_ips_path}'
                )
            else:
                raise DataException('Target provider did not provide any candidate pairs')
    else:
        log.info(f'Loading candidate file {conf.paths.candidates_csv}')
        # load candidate pairs
        ports_available, ts_data_available, tcp_opts_available, candidate_pairs = load_candidate_pairs(
            conf.paths.candidates_csv, skip_list=wiring.skip_list, include_domain=True
        )
        if not candidate_pairs:
            raise DataException(f'Candidate CSV at {conf.paths.candidates_csv} is empty')
    candidate_pairs = _reduce_map(candidate_pairs, conf, 'candidate pairs')
    ip_cp_lut = {}  # { ip: [ CandidatePair ] }
    if not ports_available or not ts_data_available:
        for ip_tuple, cp in candidate_pairs.items():
            ip4, ip6 = ip_tuple
            if ip4 in ip_cp_lut:
                ip_cp_lut[ip4].append(cp)
            else:
                ip_cp_lut[ip4] = [cp]
            if ip6 in ip_cp_lut:
                ip_cp_lut[ip6].append(cp)
            else:
                ip_cp_lut[ip6] = [cp]
    nr_candidates_written = 0
    if not ports_available:
        try:
            # no ports in csv file available -> find open ports with TSNode
            if not conf.targetprovider.has_resolved:
                log.info('No open ports available in candidate file')

            nodes4 = set()  # do not add IPs more than once
            nodes6 = set()
            for cp in candidate_pairs.values():
                nodes4.add(cp.ip4)
                nodes6.add(cp.ip6)

            log.info('Starting port scan on candidate pairs')

            cpscan = CandidatePortScan(
                nodes4, nodes6, wiring.nic, port_list=libconstants.PORT_LIST
            ).start()

            while not cpscan.finished():
                # do not choose this value too high otherwise the function will never return because
                # there always will be data available (queue.empty exception will never be raised)
                # 1.5 seconds seems to be the optimum for debug output
                cpscan.process_results(ip_cp_lut, timeout=1.5)
            cpscan.process_results(ip_cp_lut, timeout=3)
            cpscan.stop()  # must be explicitly stopped!

            log.info('Port scan on candidate pairs done.')
        finally:
            # write responding candidate pairs to file (no timestamp data!)
            if not ports_available:
                nr_candidates_written, nr_data_records_written = write_candidate_pairs(
                    candidate_pairs,
                    conf.base_dir,
                    only_active_nodes=True,
                    write_candidates=True,
                    write_ts_data=False,
                    write_tcp_opts_data=True,
                    include_domain=True
                )
    return candidate_pairs, nr_candidates_written, ports_available, ts_data_available


def show_input_summary(candidate_pairs, conf, nr_candidates_written, ports_available, trace_sets):
    if len(trace_sets) <= 0 and not conf.candidates.available:
        raise DataException('No nodes found from trace sets or candidate pairs, nothing to harvest.')
    if conf.candidates.available:
        if not ports_available:
            nr_active_nodes4 = nr_candidates_written
            nr_active_nodes6 = nr_candidates_written
        else:  # if ports are available, all loaded candidates should be active
            nr_candidates = len(candidate_pairs)
            nr_active_nodes4 = nr_candidates
            nr_active_nodes6 = nr_candidates
    else:
        nr_active_nodes4, nr_active_nodes6 = libtrace.total_number_active_nodes(trace_sets)
    total_active_nodes = nr_active_nodes4 + nr_active_nodes6
    if total_active_nodes > 0:
        log.info('IPv4 active nodes: {0} / IPv6 active nodes: {1}'.format(nr_active_nodes4, nr_active_nodes6))
        log.info('Total number active nodes: {0}'.format(total_active_nodes))


def perform_harvesting(candidate_pairs, trace_sets, conf, ts_data_available, wiring):
    if conf.flags.do_harvest and not conf.candidates.available:
        # only harvest if not already done
        if not any([ts.has_timestamp_data() for ts in trace_sets.values()]):
            log.info('Starting harvesting task ...')
            harvester = None

            try:
                harvester = TraceSetHarvester(wiring.nic, trace_sets, conf.harvester)
                harvester.start()

                while not harvester.finished():
                    harvester.process_results_running()
                harvester.process_results_final()
            finally:
                if harvester:
                    log.info('Total records processed: {0}'.format(harvester.total_records_processed()))

                log.info('Now writing harvesting data ...')
                # assumes trace sets already written to disk
                for tset in trace_sets.values():
                    tset.write_timestamp_data(conf.base_dir)

                log.info('Finished writing timestamp data')

        else:
            log.warning('TraceData for TraceSets available. Harvesting will not be performed!')

    elif conf.flags.do_harvest and conf.candidates.available:
        if not ts_data_available:
            log.info('Starting harvesting task ...')
            harvester = None

            try:
                harvester = CandidateHarvester(wiring.nic, candidate_pairs, conf.harvester)
                harvester.start()

                while not harvester.finished():
                    harvester.process_results_running()
                harvester.process_results_final()
            finally:
                if harvester:
                    log.info('Total records processed: {0}'.format(harvester.total_records_processed()))

                log.info('Now writing harvesting data ...')
                nr_candidates_written, nr_data_records_written = write_candidate_pairs(
                    candidate_pairs,
                    conf.base_dir,
                    write_candidates=False,
                    write_ts_data=True,
                    write_tcp_opts_data=False,
                    include_domain=True
                )

                if nr_data_records_written > 0:
                    ts_data_available = True  # now we have timestamp data available

        else:
            # do not harvest if timestamp data was loaded, instead print a warning
            tsfile = str(os.path.join(
                os.path.dirname(conf.paths.candidates_csv),
                libconstants.CANDIDATE_PAIRS_DATA_FILE_NAME)
            )
            log.warning('Timestamps already loaded from [{0}]'.format(tsfile))
            log.warning('Harvesting will not be performed!')
    return ts_data_available


def handle_post_tasks(candidates, conf):
    handle_ssh_keyscan(candidates, conf)
    log.info('Calculations for evaluation started ...')
    for c in candidates.values():
        try:
            c.evaluate()
        except Exception:
            log.exception('Exception during evaluation')
    log.info('Finished sibling candidate calculations')
    ##### OUTFILE #####
    if conf.candidates.out_csv:
        resultfile = pathlib.Path(conf.candidates.out_csv)
        if not resultfile.is_absolute():
            resultfile = libconstants.BASE_DIRECTORY / resultfile
        log.info('Writing resultfile [{0}] ...'.format(resultfile))
        nr_records = libsiblings.write_results(candidates.values(), resultfile,
                                               low_runtime=conf.candidates.low_runtime)
        log.info('Wrote {0} result records to file'.format(nr_records))
    ##### PLOT #####
    if conf.flags.do_print:  # plots all candidates to base_directory/const.PLOT_FILE_NAME
        log.info('Starting plot process ...')
        libsiblings.plot_all(candidates.values(), libconstants.PLOT_FILE_NAME)
        log.info('Finished printing charts')
    if not conf.candidates.out_csv and not conf.flags.do_print:
        log.info('Nothing more to do ... Exiting ...')


def handle_ssh_keyscan(candidates, conf):
    if not conf.candidates.skip_keyscan:
        log.info('Preparing ssh-keyscan ...')
        sshkeyscan = keyscan.Keyscan(
            candidates,
            directory=conf.base_dir, timeout=None,
            key_file_name=libconstants.SSH_KEYS_FILENAME,
            agent_file_name=libconstants.SSH_AGENTS_FILENAME,
            keyscan_command=libconstants.SSH_KEYSCAN_COMMAND
        )
        if not sshkeyscan.has_keys():  # assign available keys to candidates
            log.info('No keyfile found, starting ssh-keyscan processes')
            done = sshkeyscan.run(write_keyfile=True, split_output=False)  # if not available, run ssh-keyscan
            if not done:
                log.warning('No nodes to scan for SSH keys ...')
            else:
                log.info('Finished ssh-keyscan')
        else:
            keys_path = pathlib.Path(conf.base_dir, libconstants.SSH_KEYS_FILENAME)
            log.info(f'Loaded ssh keys from file [{keys_path}]')
    else:
        log.info('No ssh-keyscan requested')
    # stop here if solely ssh-keyscan was requested
    if conf.candidates.only_keyscan:
        log.info('--only-ssh-keyscan requested, exiting now ...')
        raise JustExit


def main():
    conf = config.AppConfig()
    _validate_config(conf)
    _bridge_config_to_legacy(conf, libconstants)
    wiring = bootstrap.Wiring(conf)
    bootstrap.bridge_wiring_to_legacy(wiring, libconstants)

    if not gc.isenabled():  # just to be sure ...
        gc.enable()

    # debug run requested, exiting now
    if conf.debug:
        log.warning('DEBUG run -> exiting now ...')
        raise JustExit

    log.info('Started')

    if not conf.flags.load_tracesets:
        # create base directory
        dir_status = libtools.create_directories(conf.base_dir)
        if dir_status is None:
            log.info(f'Directory [{conf.base_dir}] already exists')
        elif dir_status:
            log.info(f'Successfully created base directory [{conf.base_dir}]')
        else:  # False
            raise ConfigurationException(f'Unable to create basedir for trace sets {conf.base_dir}')

    # either trace sets ...
    trace_sets = {}  # { v4target_v6target: TraceSet() }   # trace sets to work with
    # ... or candidate pairs
    candidate_pairs = {}  # { (ip4, ip6): CandidatePair }

    ##########

    ports_available = False
    ts_data_available = False
    nr_candidates_written = 0
    if conf.flags.load_tracesets:
        log.info(f'Loading trace sets from base directory {conf.base_dir}')
        trace_sets = libtrace.load_trace_sets(
            conf.base_dir, wiring.nic, conf.paths.base_dir_silent,
            skip_list=wiring.skip_list
        )
        trace_sets = _reduce_map(trace_sets, conf, 'TraceSets')
    elif conf.flags.has_targets:
        handle_targets(trace_sets, wiring)
    elif conf.candidates.available:
        candidate_pairs, nr_candidates_written, ports_available, ts_data_available = handle_candidates(conf, wiring)
    else:
        raise ConfigurationException('No valid action requested!')

    ##########

    show_input_summary(candidate_pairs, conf, nr_candidates_written, ports_available, trace_sets)

    ts_data_available = perform_harvesting(candidate_pairs, trace_sets, conf, ts_data_available, wiring)

    candidates = prepare_evaluation(candidate_pairs, conf, trace_sets, ts_data_available)

    # whenever possible remove components of CANDIDATE_PAIRS / TRACE_SETS
    candidate_pairs.clear()
    trace_sets.clear()
    gc.collect()
    handle_post_tasks(candidates, conf)
    return 0


def prepare_evaluation(candidate_pairs, conf, trace_sets, ts_data_available):
    if conf.skip_evaluation:
        log.warning('No evaluation requested (--no-evaluation). Exiting.')
        raise JustExit
    # stop here if only portscan was requested
    only_portscan_requested = not (
            (conf.candidates.available and ts_data_available) or
            any([ts.has_timestamp_data() for ts in trace_sets.values()])
    )
    if only_portscan_requested:
        raise DataException('No timestamps available, was only a port scan requested?')
    if conf.candidates.available:
        candidates = libsiblings.construct_node_candidates(
            candidate_pairs, low_runtime=conf.candidates.low_runtime
        )
    else:
        candidates = libsiblings.construct_trace_candidates(
            trace_sets, low_runtime=conf.candidates.low_runtime
        )
    if not candidates:
        raise DataException('No sibling candidates available')
    log.info(f'Constructed {len(candidates)} sibling candidates')
    return candidates


################################################################################
################################################################################
################################################################################

if __name__ == '__main__':
    if settings.dependency_error():
        sys.exit(-1)  # do not continue ...

    if libconstants.OPTIMIZE_OS_SETTINGS or libconstants.DISABLE_TIME_SYNC_SERVICE or libconstants.FIREWALL_APPLY_RULES:
        os_settings = settings.Settings(backup_to_file=libconstants.WRITE_OS_SETTINGS_TO_FILE)

    ret = -42
    error = False

    try:
        if libconstants.OPTIMIZE_OS_SETTINGS:
            os_settings.optimize_system_config()
        if libconstants.DISABLE_TIME_SYNC_SERVICE:
            os_settings.disable_timesync()
        if libconstants.FIREWALL_APPLY_RULES:
            os_settings.enable_firewall_rules()

        ret = main()  # start main execution

    except BusinessException:
        log.exception()
        ret = -3
    except JustExit:
        ret = 0
    except Exception as e:
        error = True
        exc_type, exc_object, exc_traceback = sys.exc_info()
        ef = traceback.extract_tb(exc_traceback)[-1]  # get the inner most error frame
        string = '{0} in {1} (function: \'{2}\') at line {3}: "{4}" <{5}>'.format(exc_type.__name__,
                                                                                  os.path.basename(ef.filename),
                                                                                  ef.name, ef.lineno, str(e), ef.line)
        log.critical(string)
        print('CRITICAL: {0}'.format(string), file=sys.stderr)  # additionally print to stderr
    except (KeyboardInterrupt, SystemExit):
        error = True
        raise
    finally:
        # remove any applied firewall rules
        if libconstants.FIREWALL_APPLY_RULES:
            os_settings.disable_firewall_rules()
        # restart time sync service if it was stopped previously
        if libconstants.DISABLE_TIME_SYNC_SERVICE:
            os_settings.enable_timesync()
        # in any other case restore default settings
        if libconstants.OPTIMIZE_OS_SETTINGS:
            os_settings.restore_system_config()

    sys.exit(ret)
