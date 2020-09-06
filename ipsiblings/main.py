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
import pathlib
import random
import sys
import traceback

from ipsiblings.bootstrap.exception import ConfigurationException
from ipsiblings.libts.harvester import TraceSetHarvester, CandidateHarvester
from ipsiblings.libts.portscan import TraceSetPortScan, CandidatePortScan
from ipsiblings.libts.serialization import load_candidate_pairs, write_candidate_pairs
from ipsiblings.targetprovider import alexa
from . import cdnfilter, targetprovider
from . import keyscan
from . import libconstants as const
from . import libgeo
from . import libsiblings
from . import libtools
from . import libtrace
from . import settings
from .config import *
from .libtraceroute.cptraceroute import CPTraceroute

# setup root logger
log = liblog.setup_root_logger()
# set log level for scapy => disables warnings
liblog.set_scapy_loglevel(const.LOG_LVL_SCAPY)
# set field_size_limit() from 131072 (2**17) to 262144 (2**18)
csv.field_size_limit(262144)


def _prepare_reduce(iterable, config, kind):
    should_reduce = (config.start_index or config.end_index)
    if not iterable or not should_reduce:
        return False
    inp_len = len(iterable)
    if config.end_index is None or config.end_index > inp_len:
        config.end_index = inp_len
    if config.start_index >= config.end_index:
        log.error(f'{kind} - Start index must be less than end index ({config.start_index} to {config.end_index})')
        sys.exit(-6)
    elif config.start_index >= inp_len:
        log.error(f'{kind} - Start index exceeds available input ({config.start_index} >= {inp_len}')
        sys.exit(-6)
    else:
        return True


def _reduce_map(inp_dict, config, type):
    # Python 3.6+ preserves insertion order with built-in dict
    if not _prepare_reduce(inp_dict, config, type):
        return inp_dict
    original_len = len(inp_dict)
    keys = list(inp_dict.keys())[config.start_index: config.end_index]
    result = {key: inp_dict[key] for key in keys}
    log.info(f'Reduced loaded {type} from size [{original_len}] to [{len(result)}] '
             f'(indices [{config.start_index}] to [{config.end_index}])')
    return result


def _reduce_list(inp_list, config, type):
    if not _prepare_reduce(inp_list, config, type):
        return inp_list
    original_len = len(inp_list)
    result = inp_list[config.start_index: config.end_index]
    log.info(f'Reduced loaded {type} from size [{original_len}] to [{len(result)}] '
             f'(indices [{config.start_index}] to [{config.end_index}])')
    return result


def _validate_config(config):
    if config.targetprovider.resolved_ips_path and not config.targetprovider.has_resolved:
        print_usage_and_exit('-f/--resolved-file can only be used with -s/--resolved')

    if config.targetprovider.do_download and not config.targetprovider.has_resolved:
        print_usage_and_exit('-o/--download-alexa can only be used with -s/--resolved')

    if config.end_index is not None:
        if config.start_index < 0 or config.end_index < 1:
            print_usage_and_exit('--from/--to can not be negative/zero')
        if config.start_index >= config.end_index:
            print_usage_and_exit('--to can not be less or equal to --from')


def _apply_config(config):
    log.setLevel(config.log_level)
    const.BASE_DIRECTORY = config.base_dir
    # PORT_LIST selection based on --router-ports/--server-ports options or operation mode (-c/-t)
    # prioritize the explicit arguments
    if config.port_scan.router_portlist:
        const.PORT_LIST = const.PORT_LIST_ROUTER
    elif config.port_scan.server_portlist:
        const.PORT_LIST = const.PORT_LIST_SERVER
    else:
        if config.candidates.available:
            const.PORT_LIST = const.PORT_LIST_SERVER
        elif config.flags.has_targets or config.flags.load_tracesets:
            const.PORT_LIST = const.PORT_LIST_ROUTER
        else:
            const.PORT_LIST = const.PORT_LIST_SERVER

    const.GEO = libgeo.Geo(config)


def _find_ds_interface():
    log.debug('Searching for Dual Stack interfaces ...')
    nic = None  # network interface to use
    nic_list = libtools.get_dualstack_nics()
    if not nic_list:
        log.error('You do not have any Dual Stack interface available! Exiting ...')
        return False
    else:
        nic = nic_list[0]
    log.info(f'Found Dual Stack interfaces: {nic_list}, using \'{nic}\'')

    const.IFACE_MAC_ADDRESS = libtools.get_mac(iface=nic).lower()
    if const.IFACE_MAC_ADDRESS:
        log.debug(f'Identified MAC address: {const.IFACE_MAC_ADDRESS}')

    own_ip4, own_ip6 = libtools.get_iface_IPs(iface=nic)
    const.IFACE_IP4_ADDRESS = own_ip4
    const.IFACE_IP6_ADDRESS = own_ip6.lower()
    if const.IFACE_IP4_ADDRESS and const.IFACE_IP6_ADDRESS:
        log.debug(f'Identified IP addresses [{nic}]: {const.IFACE_IP4_ADDRESS} / {const.IFACE_IP6_ADDRESS}')
    return nic


def main():
    config = AppConfig()
    _validate_config(config)
    _apply_config(config)

    if not gc.isenabled():  # just to be sure ...
        gc.enable()

    # debug run requested, exiting now
    if config.debug:
        log.warning('DEBUG run -> exiting now ...')
        return 0

    log.info('Started')

    nic = _find_ds_interface()
    if not nic:
        return -2

    v4bl_re, v6bl_re = libtools.construct_blacklist_regex(config.paths.ip_ignores)
    if v4bl_re or v6bl_re:
        log.debug(f'Constructed blacklist filters from {config.paths.ip_ignores}')

    if not config.flags.load_tracesets:
        # create base directory
        dir_status = libtools.create_directories(config.base_dir)
        if dir_status is None:
            log.info(f'Directory [{config.base_dir}] already exists')
        elif dir_status:
            log.info(f'Successfully created base directory [{config.base_dir}]')
        else:  # False
            log.error(f'Error while creating base directory [{config.base_dir}]')
            return -3

    target_provider = targetprovider.get_provider(config.targetprovider.provider)

    # either trace sets ...
    TRACE_SETS = {}  # { v4target_v6target: TraceSet() }   # trace sets to work with
    SILENT_TRACE_SETS = {}  # trace sets with non responding nodes
    # ... or candidate pairs
    CANDIDATE_PAIRS = {}  # { (ip4, ip6): CandidatePair }

    CDN_FILTERED = {}  # { (ip4, ip6): [domains] }

    ##########

    if config.flags.load_tracesets:
        log.info(f'Loading trace sets from base directory {config.base_dir}')
        TRACE_SETS = libtrace.load_trace_sets(
            config.base_dir, config.paths.base_dir_silent,
            v4bl_re=v4bl_re, v6bl_re=v6bl_re, iface=nic
        )
        TRACE_SETS = _reduce_map(TRACE_SETS, config, 'TraceSets')

    elif config.flags.has_targets:  # config.paths.target_csv is not None:
        if config.targetprovider.has_resolved:
            include_domain = True
            # keep in mind that slicing does not yield deterministic results if one_per_domain is True
            ipdata = target_provider.provide_targets()
            # gives ~250k targets for 145k resolved hosts of Alexa Top List
            if not ipdata:
                if config.targetprovider.resolved_ips_path:
                    log.error(f'{config.targetprovider.resolved_ips_path}: Empty CSV file!')
                else:
                    log.error('Empty target array!')
                return -3
        else:
            include_domain = False
            ipdata = libtools.parsecsv(config.paths.target_csv, iponly=True, include_domain=include_domain)
            if not ipdata:
                log.error(f'{config.paths.target_csv}: Empty CSV file!')
                return -3

        log.info(f'Constructed {len(ipdata)} candidates')
        if config.candidates.write_pairs:
            nr_records = libtools.write_constructed_pairs(
                pathlib.Path(config.base_dir) / config.candidates.write_pairs,
                ipdata,
                include_domain=include_domain
            )
            log.info('Wrote [{0}] IP candidate pairs to [{1}]'.format(nr_records, str(
                pathlib.Path(config.base_dir) / config.candidates.write_pairs)))
            log.info('Exiting now ...')
            return 0

        ipdata = _reduce_list(ipdata, config, 'targets (ipdata)')
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
                if key in TRACE_SETS:  # should never happen
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
                        (ip4, ip6), iface=nic, algorithm='traceroute', timeout=2
                    ).traceroute(result_timeout=3)

                    # check for CDN after very few hops
                    # if config.paths.cdns:
                    #   if len(ip4tracert) < const.CDN_HOP_THRESHOLD or len(ip6tracert) < const.CDN_HOP_THRESHOLD:
                    #     if const.CDNFILTER.is_cdn(ip4, ip6):
                    #       CDN_FILTERED[(ip4, ip6)] = domains
                    #       break # stop and do not inspect CDN target

                    try:
                        trace = libtrace.Trace().init(
                            ip4, ip6, ip4tracert, ip6tracert,
                            v4bl_re=v4bl_re, v6bl_re=v6bl_re, iface=nic
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
                            log.debug('No trace data available for target ({0} / {1})! [{2}. retry]'.format(ip4, ip6,
                                                                                                            no_new_trace_counter))

                        if no_new_trace_counter >= const.MAX_TRIES_FOR_NEW_TRACE:
                            break
                        continue

                    nodes4, nodes6 = trace.get_global_valid_IPs(
                        apply_ignore_regex=bool(config.paths.ip_ignores))  # only apply regex if ignore file was given

                    tsports = TraceSetPortScan(nodes4, nodes6, port_list=const.PORT_LIST, iface=nic).start()
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
                    TRACE_SETS[key] = trace_set
                else:
                    SILENT_TRACE_SETS[key] = trace_set
        finally:
            ts_written = libtrace.write_trace_sets(config.base_dir, TRACE_SETS)
            if const.WRITE_INACTIVE_TRACE_SET:
                ts_silent_written = libtrace.write_trace_sets(config.paths.base_dir_silent, SILENT_TRACE_SETS)
                if ts_written > 0 or ts_silent_written > 0:
                    log.info('Active TraceSets written: {0} / Inactive TraceSets written: {1}'.format(ts_written,
                                                                                                      ts_silent_written))
            else:
                if ts_written > 0:
                    log.info('Active TraceSets written: {0}'.format(ts_written))

            filtered_cdns_written = cdnfilter.write_filtered(config.base_dir, CDN_FILTERED,
                                                             include_domain=include_domain)
            if filtered_cdns_written > 0:
                log.info('Filtered CDN pairs written: {0}'.format(filtered_cdns_written))

    ##########

    elif config.candidates.available:  # elif config.paths.candidates_csv is not None:

        if config.targetprovider.has_resolved:
            ports_available = False
            ts_data_available = False
            CANDIDATE_PAIRS = target_provider.provide_candidates()
            if not CANDIDATE_PAIRS:
                if config.targetprovider.resolved_ips_path:
                    log.error('{0}: Empty file!'.format(config.targetprovider.resolved_ips_path))
                else:
                    log.error('Empty candidate pairs!')
                return -3
        else:
            log.info('Loading candidate file {0}'.format(config.paths.candidates_csv))
            # load candidate pairs
            ports_available, ts_data_available, tcp_opts_available, CANDIDATE_PAIRS = load_candidate_pairs(
                config.paths.candidates_csv, v4bl_re=v4bl_re, v6bl_re=v6bl_re, include_domain=True
            )
            if not CANDIDATE_PAIRS:
                log.error('{0}: Empty file!'.format(config.paths.candidates_csv))
                return -3

        CANDIDATE_PAIRS = _reduce_map(CANDIDATE_PAIRS, config, 'candidate pairs')

        try:
            if not ports_available or not ts_data_available:
                ip_cp_lut = {}  # { ip: [ CandidatePair ] }

                for ip_tuple, cp in CANDIDATE_PAIRS.items():
                    ip4, ip6 = ip_tuple
                    if ip4 in ip_cp_lut:
                        ip_cp_lut[ip4].append(cp)
                    else:
                        ip_cp_lut[ip4] = [cp]
                    if ip6 in ip_cp_lut:
                        ip_cp_lut[ip6].append(cp)
                    else:
                        ip_cp_lut[ip6] = [cp]

            if not ports_available:
                # no ports in csv file available -> find open ports with TSNode
                if not config.targetprovider.has_resolved:
                    log.info('No open ports available in candidate file')

                nodes4 = set()  # do not add IPs more than once
                nodes6 = set()
                for cp in CANDIDATE_PAIRS.values():
                    nodes4.add(cp.ip4)
                    nodes6.add(cp.ip6)

                log.info('Starting open port identification')

                cpscan = CandidatePortScan(nodes4, nodes6, port_list=const.PORT_LIST, iface=nic).start()

                while not cpscan.finished():
                    # do not choose this value too high otherwise the function will never return because
                    # there always will be data available (queue.empty exception will never be raised)
                    cpscan.process_results(
                        ip_cp_lut, timeout=1.5
                    )  # 1.5 seconds seems to be the optimum for debug output
                cpscan.process_results(ip_cp_lut, timeout=3)  # was 5
                cpscan.stop()  # must be explicitly stopped!

                log.info('Finished with port identification')
        finally:
            # write responding candidate pairs to file (no timestamp data!)
            if not ports_available:
                nr_candidates_written, nr_data_records_written = write_candidate_pairs(
                    CANDIDATE_PAIRS,
                    config.base_dir,
                    only_active_nodes=True,
                    write_candidates=True,
                    write_ts_data=False,
                    write_tcp_opts_data=True,
                    include_domain=True
                )

    ##########

    else:
        log.critical('Should never reach here ...')
        raise RuntimeError('Undefined program flow')

    ##########

    if not len(TRACE_SETS) > 0 and not config.candidates.available:
        log.warning('No active nodes available!')
        return 0

    if config.candidates.available:
        if not ports_available:
            nr_active_nodes4 = nr_candidates_written
            nr_active_nodes6 = nr_candidates_written
        else:  # if ports are available, all loaded candidates should be active
            nr_candidates = len(CANDIDATE_PAIRS)
            nr_active_nodes4 = nr_candidates
            nr_active_nodes6 = nr_candidates
    else:
        nr_active_nodes4, nr_active_nodes6 = libtrace.total_number_active_nodes(TRACE_SETS)

    total_active_nodes = nr_active_nodes4 + nr_active_nodes6
    if total_active_nodes > 0:
        log.info('IPv4 active nodes: {0} / IPv6 active nodes: {1}'.format(nr_active_nodes4, nr_active_nodes6))
        log.info('Total number active nodes: {0}'.format(total_active_nodes))

    ### HARVESTING STARTS HERE ###
    ##############################

    if config.flags.do_harvest and not config.candidates.available:
        # only harvest if not already done
        if not any([ts.has_timestamp_data() for ts in TRACE_SETS.values()]):
            log.info('Starting harvesting task ...')

            try:
                harvester = TraceSetHarvester(
                    TRACE_SETS, runtime=const.HARVESTING_RUNTIME, interval=const.HARVESTING_INTERVAL, iface=nic
                )
                harvester.start()

                while not harvester.finished():
                    harvester.process_results(timeout=const.HARVESTING_RESULTS_TIMEOUT)
                harvester.process_results(timeout=const.HARVESTING_RESULTS_TIMEOUT_FINAL)
            finally:
                log.info('Total records processed: {0}'.format(harvester.total_records_processed()))

                log.info('Now writing harvesting data ...')
                # assumes trace sets already written to disk
                for tset in TRACE_SETS.values():
                    tset.write_timestamp_data(config.base_dir)

                log.info('Finished writing timestamp data')

        else:
            log.warning('TraceData for TraceSets available. Harvesting will not be performed!')

    elif config.flags.do_harvest and config.candidates.available:
        if not ts_data_available:
            log.info('Starting harvesting task ...')

            try:
                harvester = CandidateHarvester(
                    CANDIDATE_PAIRS, runtime=const.HARVESTING_RUNTIME, interval=const.HARVESTING_INTERVAL, iface=nic
                )
                harvester.start()

                while not harvester.finished():
                    harvester.process_results(timeout=const.HARVESTING_RESULTS_TIMEOUT)
                harvester.process_results(timeout=const.HARVESTING_RESULTS_TIMEOUT_FINAL)
            finally:
                log.info('Total records processed: {0}'.format(harvester.total_records_processed()))
                log.info('Now writing harvesting data ...')

                nr_candidates_written, nr_data_records_written = write_candidate_pairs(
                    CANDIDATE_PAIRS,
                    config.base_dir,
                    write_candidates=False,
                    write_ts_data=True,
                    write_tcp_opts_data=False,
                    include_domain=True
                )

                if nr_data_records_written > 0:
                    ts_data_available = True  # now we have timestamp data available

        else:
            # do not harvest if timestamp data was loaded, instead print a warning
            tsfile = str(
                os.path.join(os.path.dirname(config.paths.candidates_csv), const.CANDIDATE_PAIRS_DATA_FILE_NAME))
            log.warning('Timestamps already loaded from [{0}]'.format(tsfile))
            log.warning('Harvesting will not be performed!')

    ##########

    # stop here if no evaluation was requested
    if config.skip_evaluation:
        log.warning('No evaluation requested (--no-evaluation). Exiting.')
        return 0

    # stop here if only portscan was requested
    if (config.candidates.available and ts_data_available) or any(
            [ts.has_timestamp_data() for ts in TRACE_SETS.values()]):
        candidates = None
        if config.candidates.available:
            candidates = libsiblings.construct_node_candidates(
                CANDIDATE_PAIRS, low_runtime=config.candidates.low_runtime
            )
        else:
            candidates = libsiblings.construct_trace_candidates(
                TRACE_SETS, low_runtime=config.candidates.low_runtime
            )

        if not candidates:
            log.warning('No candidates available!')
            return 0

        log.info('Constructed {0} sibling candidates'.format(len(candidates)))

    else:
        log.info('No evaluation without timestamp data possible ... Now exiting ...')
        return 0

    # whenever possible remove components of CANDIDATE_PAIRS / TRACE_SETS
    CANDIDATE_PAIRS.clear()
    TRACE_SETS.clear()
    gc.collect()

    ##### SSH-KEYSCAN #####
    if not config.candidates.skip_keyscan:
        log.info('Preparing ssh-keyscan ...')
        sshkeyscan = keyscan.Keyscan(
            candidates,
            directory=config.base_dir, timeout=None,
            key_file_name=const.SSH_KEYS_FILENAME,
            agent_file_name=const.SSH_AGENTS_FILENAME,
            keyscan_command=const.SSH_KEYSCAN_COMMAND
        )
        if not sshkeyscan.has_keys():  # assign available keys to candidates
            log.info('No keyfile found, starting ssh-keyscan processes')
            done = sshkeyscan.run(write_keyfile=True, split_output=False)  # if not available, run ssh-keyscan
            if not done:
                log.warning('No nodes to scan for SSH keys ...')
            else:
                log.info('Finished ssh-keyscan')
        else:
            keys_path = pathlib.Path(config.base_dir, const.SSH_KEYS_FILENAME)
            log.info(f'Loaded ssh keys from file [{keys_path}]')
    else:
        log.info('No ssh-keyscan requested')

    # stop here if solely ssh-keyscan was requested
    if config.candidates.only_keyscan:
        log.info('--only-ssh-keyscan requested, exiting now ...')
        return 0

    ##### EVALUATE #####
    log.info('Calculations for evaluation started ...')
    for c in candidates.values():
        try:
            c.evaluate()
        except Exception as e:
            log.warning('exception during evaluation', exc_info=e)
    log.info('Finished sibling candidate calculations')

    ##### OUTFILE #####
    if config.candidates.out_csv:
        resultfile = pathlib.Path(config.candidates.out_csv)
        if not resultfile.is_absolute():
            resultfile = const.BASE_DIRECTORY / resultfile
        log.info('Writing resultfile [{0}] ...'.format(resultfile))
        nr_records = libsiblings.write_results(candidates.values(), resultfile,
                                               low_runtime=config.candidates.low_runtime)
        log.info('Wrote {0} result records to file'.format(nr_records))

    ##### PLOT #####
    if config.flags.do_print:  # plots all candidates to base_directory/const.PLOT_FILE_NAME
        log.info('Starting plot process ...')
        libsiblings.plot_all(candidates.values(), const.PLOT_FILE_NAME)
        log.info('Finished printing charts')

    if not config.candidates.out_csv and not config.flags.do_print:
        log.info('Nothing more to do ... Exiting ...')

    return 0


################################################################################
################################################################################
################################################################################

if __name__ == '__main__':
    if settings.dependency_error():
        sys.exit(-1)  # do not continue ...

    if const.OPTIMIZE_OS_SETTINGS or const.DISABLE_TIME_SYNC_SERVICE or const.FIREWALL_APPLY_RULES:
        os_settings = settings.Settings(backup_to_file=const.WRITE_OS_SETTINGS_TO_FILE)

    ret = -42
    error = False

    try:
        if const.OPTIMIZE_OS_SETTINGS:
            os_settings.optimize_system_config()
        if const.DISABLE_TIME_SYNC_SERVICE:
            os_settings.disable_timesync()
        if const.FIREWALL_APPLY_RULES:
            os_settings.enable_firewall_rules()

        ret = main()  # start main execution

    except ConfigurationException:
        log.exception()
        ret = -3
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
        if const.FIREWALL_APPLY_RULES:
            os_settings.disable_firewall_rules()
        # restart time sync service if it was stopped previously
        if const.DISABLE_TIME_SYNC_SERVICE:
            os_settings.enable_timesync()
        # in any other case restore default settings
        if const.OPTIMIZE_OS_SETTINGS:
            os_settings.restore_system_config()

    sys.exit(ret)
