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

##### CURRENT IGNORE FILE ######################################################
# # rackspace
# 10.*
# 50.56.6.*
# # end rackspace
# # netcup
# 185.170.112.2
# 185.170.112.3
# # end netcup
# =
# # rackspace
# 2001:4801:800:dc1:ca::
# 2001:4801:800:ca:bb99::
# 2001:4801:800:dc2:cb::
# # end rackspace
# # netcup
# 2a03:4000:ffff:ffff::2
# 2a03:4000:15::2
# # end netcup
################################################################################

import argparse
import csv
import gc
import os
import pathlib
import random
import sys
import textwrap
import time
import traceback

from . import cdnfilter
from . import keyscan
from . import libconstants as const
from . import libgeo
from . import liblog
from . import libsiblings
from . import libtools
from . import libtrace
from . import libtraceroute
from . import libts
from . import resolved
from . import settings

# setup root logger
log = liblog.setup_root_logger()
# set log level for scapy => disables warnings
liblog.set_scapy_loglevel(const.LOG_LVL_SCAPY)
# set field_size_limit() from 131072 (2**17) to 262144 (2**18)
csv.field_size_limit(262144)


def _prepare_arg_parser():
    ap = argparse.ArgumentParser(
        description=textwrap.dedent('''\
        IP Siblings Toolset

        The argument of -c/-t option (combined with -s option) can be used with alexa
        top list file if resolution is required.
        [Any other file formatted in that way can be used.]'''),
        # why this: ?
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    # reproduction of argparse behavior on error
    # ap.print_usage(sys.stderr)
    # prog = os.path.basename(sys.argv[0])
    # sys.stderr.write('{0}: error: error description goes here\n'.format(prog))
    # sys.exit(2)

    one_grp = ap.add_argument_group(title='required argument, exactly one', description=None)
    mutualgrp = one_grp.add_mutually_exclusive_group(required=True)
    mutualgrp.add_argument('-c', '--candidates', action='store', help='parse candidates from csv file or top list (-s)',
                           default=None, nargs='?', const='None')
    mutualgrp.add_argument('-t', '--trace-targets', action='store',
                           help='trace target hosts from csv file or top list (-s)', default=None, nargs='?',
                           const='None')
    # -l also works for already constructed TraceSets in combination with Alexa/Cisco Top list
    mutualgrp.add_argument('-l', '--load', action='store_true',
                           help='load previously saved trace sets from base directory', default=False)
    mutualgrp.add_argument('--alexa-toplist', action='store', dest='alexa_toplist_dir',
                           help='loads the alexa top list from the internet and saves it to the given directory or current working directory',
                           default=None, nargs='?', const='cwd')
    # mutualgrp.add_argument('--cisco-toplist', action = 'store', dest = 'cisco_toplist_dir', help = 'loads the cisco top list from the internet and saves it to the given directory or current working directory', default = None, nargs = '?', const = 'cwd')
    mutualgrp.add_argument('--debug', action='store_true', help='debug run (only run initialization)', default=False)

    opt_grp = ap.add_argument_group(title='optional arguments', description=None)
    opt_grp.add_argument('-h', '--help', action='help', help='show this help message and exit')
    opt_grp.add_argument('-d', '--directory', action='store', help='base directory to store and load trace sets',
                         default=None)
    opt_grp.add_argument('-i', '--ignore-file', action='store', help='nodes to ignore are listed in this file',
                         default=None)
    opt_grp.add_argument('-r', '--run-harvest', action='store_true', help='perform harvesting for candidate IPs',
                         default=False)
    opt_grp.add_argument('-s', '--resolved', action='store_true',
                         help='construct candidates or trace targets from resolved (alexa top) list (use with -c/-t for operation mode)',
                         default=False)
    opt_grp.add_argument('-f', '--resolved-file', action='store',
                         help='csv file holding resolved (alexa) domains and IPs', default=None)
    opt_grp.add_argument('-o', '--download-alexa', action='store_true',
                         help='allows downloading alexa top list from the internet', default=False)
    opt_grp.add_argument('--router-ports', action='store_true',
                         help='use the comprehensive port list for non-server devices', default=False)
    opt_grp.add_argument('--server-ports', action='store_true', help='use the much smaller port list for servers',
                         default=False)
    opt_grp.add_argument('--from', action='store', type=int, dest='start_index',
                         help='restricts candidates/targets to a start index', default=None)
    opt_grp.add_argument('--to', action='store', type=int, dest='end_index',
                         help='restricts candidates/targets to an end index (excluded)', default=None)
    opt_grp.add_argument('--low-runtime', action='store_true', help='use only few timestamps for evaluation',
                         default=False)
    opt_grp.add_argument('--print', action='store_true', help='print charts to pdf file', default=False)
    opt_grp.add_argument('--resultfile', action='store', help='write evaluation results to file', default=None,
                         nargs='?', const=const.RESULT_FILE_NAME)
    opt_grp.add_argument('--no-evaluation', action='store_true',
                         help='do not perform any calculations/evaluations on sibling candidates', default=False)
    opt_grp.add_argument('--cdn-file', action='store', help='load CDN networks for IP filtering', default=None)
    opt_grp.add_argument('--write-pairs', action='store', help='write constructed IP pairs to file', default=None,
                         nargs='?', const=const.IP_PAIRS_FILE_NAME)
    opt_grp.add_argument('--no-ssh-keyscan', action='store_true', help='do not scan for public ssh keys', default=False)
    opt_grp.add_argument('--only-ssh-keyscan', action='store_true', help='exit after keyscan', default=False)

    log_grp = ap.add_argument_group(title='optional logging arguments', description=None)
    logmutualgrp = log_grp.add_mutually_exclusive_group()
    logmutualgrp.add_argument('-v', '--verbose', action='count', help='increase verbosity once per call', default=0)
    logmutualgrp.add_argument('-q', '--quiet', action='count', help='decrease verbosity once per call', default=0)

    geo_grp = ap.add_argument_group(title='optional geolocation arguments', description=None)
    geo_grp.add_argument('--city-db', action='store', help='custom MaxMind city database', default=None)
    geo_grp.add_argument('--asn-db', action='store', help='custom MaxMind ASN database', default=None)
    geo_grp.add_argument('--update-geo-dbs', action='store_true', help='update geolocation databases', default=False)

    return ap


def main():
    ap = _prepare_arg_parser()
    args = ap.parse_args()

    verbosity = args.verbose - args.quiet
    if verbosity <= -2:
        loglevel = liblog.CRITICAL
    elif verbosity <= -1:
        loglevel = liblog.ERROR
    elif verbosity == 0:  # no parameter provided
        loglevel = liblog.WARNING
    elif verbosity == 1:
        loglevel = liblog.INFO
    else:
        loglevel = liblog.DEBUG

    log.setLevel(loglevel)

    ARGS_debug = args.debug  # run initialization only for debugging reasons

    # base directory where data will be read from or written to
    if args.directory:  # direcotry provided
        ARGS_base_dir = os.path.join(args.directory, '')
    else:
        ARGS_base_dir = os.path.join(const.BASE_DIRECTORY, time.strftime("%Y-%m-%d_%H.%M.%S"))

    const.BASE_DIRECTORY = ARGS_base_dir  # set base dir for current execution instance
    # trace sets without answering nodes will be written to this directory
    base_dir_silent = os.path.join(ARGS_base_dir, const.DIRECTORY_SILENT_NODES, '')

    ARGS_ip_ignore_file = args.ignore_file

    # True: load trace set data from base direcotry; False: run active node discovery with given csv file
    ARGS_load_tracesets = args.load
    # trace targets csv file
    ARGS_target_csv_file = args.trace_targets
    # examine nodes given in candidate csv file
    ARGS_candidates_csv_file = args.candidates

    ARGS_alexa_toplist_dir = args.alexa_toplist_dir
    if ARGS_alexa_toplist_dir is not None:  # download alexa top list and save it to directory
        if ARGS_alexa_toplist_dir == 'cwd':
            directory = os.getcwd()
        else:
            directory = ARGS_alexa_toplist_dir

        extracted = resolved.Alexa.load_remote_toplist(directory)  # staticmethod
        if extracted:
            log.info('Successfully downloaded and extracted Alexa Top List file [{0}]'.format(extracted))
            return 0
        else:
            log.error('Could not download/write file to disk [{0}]'.format(directory))
            return -3
        # return at this point

    # True: perform harvesting task for the identified trace sets or the loaded candidates
    ARGS_perform_harvesting = args.run_harvest

    # resolved argument given -> work with resolved files
    ARGS_resolved = args.resolved
    ARGS_resolved_file = args.resolved_file
    ARGS_download_alexa = args.download_alexa
    if ARGS_resolved_file and not ARGS_resolved:
        ap.print_usage(sys.stderr)
        prog = os.path.basename(sys.argv[0])
        sys.stderr.write('{0}: error: -f/--resolved-file can only be used with -s/--resolved\n'.format(prog))
        sys.exit(2)

    if ARGS_download_alexa and not ARGS_resolved:
        ap.print_usage(sys.stderr)
        prog = os.path.basename(sys.argv[0])
        sys.stderr.write('{0}: error: -o/--download-alexa can only be used with -s/--resolved\n'.format(prog))
        sys.exit(2)

    # start_index, end_index to restrict amount of data to process
    ARGS_start_index = args.start_index
    ARGS_end_index = args.end_index
    if ARGS_start_index is None:
        ARGS_start_index = 0
    if ARGS_end_index is not None:
        if ARGS_start_index < 0 or ARGS_end_index < 1:
            ap.print_usage(sys.stderr)
            prog = os.path.basename(sys.argv[0])
            sys.stderr.write('{0}: error: --from/--to can not be negative/zero\n'.format(prog))
            sys.exit(2)
        if ARGS_start_index >= ARGS_end_index:
            ap.print_usage(sys.stderr)
            prog = os.path.basename(sys.argv[0])
            sys.stderr.write('{0}: error: --to can not be less or equal to --from\n'.format(prog))
            sys.exit(2)

    # individual geolocation databases
    ARGS_city_db = args.city_db
    ARGS_asn_db = args.asn_db
    ARGS_update_geo_dbs = args.update_geo_dbs

    # determine if we deal with concrete (submitted) nodes or trace sets containing candidate nodes
    ARGS_candidates_available = bool(
        ARGS_candidates_csv_file)  # evaluate to true if no additional argument for -c/-t is given
    ARGS_targets_available = bool(
        ARGS_target_csv_file)  # this allows us to distinguish whether candidate or target tasks should be performed

    ARGS_router_portlist = args.router_ports
    ARGS_server_portlist = args.server_ports

    ARGS_lowruntime = args.low_runtime
    ARGS_print = args.print
    ARGS_resultfile = args.resultfile
    ARGS_no_evaluation = args.no_evaluation
    ARGS_cdn_file = args.cdn_file
    ARGS_write_pairs = args.write_pairs
    ARGS_no_ssh_keyscan = args.no_ssh_keyscan
    ARGS_only_ssh_keyscan = args.only_ssh_keyscan

    # PORT_LIST selection based on --router-ports/--server-ports options or operation mode (-c/-t)
    # prioritize the explicit arguments
    if ARGS_router_portlist:
        const.PORT_LIST = const.PORT_LIST_ROUTER
    elif ARGS_server_portlist:
        const.PORT_LIST = const.PORT_LIST_SERVER
    else:
        if ARGS_candidates_available:
            const.PORT_LIST = const.PORT_LIST_SERVER
        elif ARGS_targets_available or ARGS_load_tracesets:
            const.PORT_LIST = const.PORT_LIST_ROUTER
        else:
            const.PORT_LIST = const.PORT_LIST_SERVER

    # initialize global Geolocation object
    geo = libgeo.Geo(city_db_path=ARGS_city_db, asn_db_path=ARGS_asn_db)
    const.GEO = geo  # make Geo object available to other modules which use constants
    # update databases if requested
    if ARGS_update_geo_dbs:
        const.GEO.update_databases()  # does nothing if no updates available

    ###

    if not gc.isenabled():  # just to be sure ...
        gc.enable()

    #### TEST CODE ####
    # code to test goes here
    ####

    # debug run requested, exiting now
    if ARGS_debug:
        log.warning('DEBUG run -> exiting now ...')
        return 0

    ###

    log.info('Started')

    log.debug('Searching for Dual Stack interfaces ...')
    nic = None  # network interface to use
    nic_list = libtools.get_dualstack_nics()
    if not nic_list:
        log.error('You do not have any Dual Stack interface available! Exiting ...')
        return -2
    else:
        nic = nic_list[0]
    log.info('Found Dual Stack interfaces: {0}, using \'{1}\''.format(nic_list, nic))

    const.IFACE_MAC_ADDRESS = libtools.get_mac(iface=nic).lower()
    if const.IFACE_MAC_ADDRESS:
        log.debug('Identified MAC address: {0}'.format(const.IFACE_MAC_ADDRESS))

    own_ip4, own_ip6 = libtools.get_iface_IPs(iface=nic)
    const.IFACE_IP4_ADDRESS = own_ip4
    const.IFACE_IP6_ADDRESS = own_ip6.lower()
    if const.IFACE_IP4_ADDRESS and const.IFACE_IP6_ADDRESS:
        log.debug(
            'Identified IP addresses [{0}]: {1} / {2}'.format(nic, const.IFACE_IP4_ADDRESS, const.IFACE_IP6_ADDRESS))

    v4bl_re, v6bl_re = libtools.construct_blacklist_regex(ARGS_ip_ignore_file)
    if v4bl_re or v6bl_re:
        log.debug('Constructed blacklist filters from {0}'.format(ARGS_ip_ignore_file))

    if not ARGS_load_tracesets:
        # create base directory
        dir_status = libtools.create_directories(ARGS_base_dir)
        if dir_status == True:
            log.info('Successfully created base directory [{0}]'.format(ARGS_base_dir))
        elif dir_status is None:
            log.info('Directory [{0}] already exists'.format(ARGS_base_dir))
        else:  # False
            log.error('Error while creating base directory [{0}]'.format(ARGS_base_dir))
            return -3

    #### Alexa / resolved file
    ##############
    # prepare Alexa Top list related tasks
    if ARGS_resolved:
        if ARGS_candidates_available:  # -c
            if ARGS_candidates_csv_file == 'None':  # no additional argument given with -c
                toplist_file = None
            else:
                toplist_file = ARGS_candidates_csv_file
        elif ARGS_targets_available:  # -t
            if ARGS_target_csv_file == 'None':  # no additional argument given with -t
                toplist_file = None
            else:
                toplist_file = ARGS_target_csv_file
        else:  # should never happen
            toplist_file = None  # os.path.join(ARGS_base_dir, const.ALEXA_FILE_NAME)

        if ARGS_resolved_file:
            resolved_file = ARGS_resolved_file
        else:  # if not explicitly given, try to locate the file in base_dir (assume alexa resolved file)
            resolved_file = os.path.join(ARGS_base_dir, const.ALEXA_RESOLVED_FILE_NAME)

        const.ALEXA = resolved.Alexa(resolved_file=resolved_file)

        if not const.ALEXA.resolved_available():
            if const.ALEXA.load_toplist_file(toplist_file, remote=ARGS_download_alexa):
                if toplist_file:  # only report if loaded from file
                    log.info('Successfully loaded Alexa Top List file [{0}]'.format(toplist_file))
                log.info('Starting name resolution process ...')
                const.ALEXA.resolve_toplist(write_unresolvable=True)  # this will take a long time ...
            else:
                log.error('Aborting now ...')
                return -5

    if ARGS_cdn_file:
        const.CDNFILTER = cdnfilter.CDNFilter(ARGS_cdn_file)
    ####

    # either trace sets ...
    TRACE_SETS = {}  # { v4target_v6target: TraceSet() }   # trace sets to work with
    SILENT_TRACE_SETS = {}  # trace sets with non responding nodes
    # ... or candidate pairs
    CANDIDATE_PAIRS = {}  # { (ip4, ip6): CandidatePair }

    CDN_FILTERED = {}  # { (ip4, ip6): [domains] }

    ##########

    if ARGS_load_tracesets:

        log.info('Loading trace sets from base directory {0}'.format(ARGS_base_dir))
        TRACE_SETS = libtrace.load_trace_sets(ARGS_base_dir, base_dir_silent, v4bl_re=v4bl_re, v6bl_re=v6bl_re,
                                              iface=nic)
        # Python 3.6+ preserves insertion order with built-in dict
        if TRACE_SETS and (ARGS_start_index or ARGS_end_index):  # slice the data set as requested
            trace_sets_length = len(TRACE_SETS)
            if ARGS_end_index is None or ARGS_end_index > trace_sets_length:  # end_index == 0 - case already checked above
                ARGS_end_index = trace_sets_length

            if ARGS_start_index >= ARGS_end_index:
                log.error(
                    'Start index can not be higher/equal than end index (start/end: {0} / {1})'.format(ARGS_start_index,
                                                                                                       ARGS_end_index))
                return -6
            elif ARGS_start_index > trace_sets_length:
                log.error(
                    'Start index is higher than the number of TraceSets available (start index / data size: {0} / {1}'.format(
                        ARGS_start_index, trace_sets_length))
                return -6

            keys = list(TRACE_SETS.keys())[ARGS_start_index: ARGS_end_index]
            TRACE_SETS = {key: TRACE_SETS[key] for key in keys}

            log.info('Reduced loaded TraceSets from size [{0}] to [{1}] (indices from [{2}] to [{3}])'.format(
                trace_sets_length, len(TRACE_SETS), ARGS_start_index, ARGS_end_index))

    ##########

    elif ARGS_targets_available:  # ARGS_target_csv_file is not None:

        ipdata = []
        include_domain = None

        if ARGS_resolved:
            include_domain = True
            # keep in mind that slicing does not yield deterministic results if one_per_domain is True
            ipdata = const.ALEXA.construct_targets(
                one_per_domain=False)  # gives ~250k targets for 145k resolved hosts of Alexa Top List
            if not ipdata:
                if ARGS_resolved_file:
                    log.error('{0}: Empty CSV file!'.format(ARGS_resolved_file))
                else:
                    log.error('Empty target array!')
                return -3
        else:
            include_domain = False
            ipdata = libtools.parsecsv(ARGS_target_csv_file, iponly=True, include_domain=include_domain)
            if not ipdata:
                log.error('{0}: Empty CSV file!'.format(ARGS_target_csv_file))
                return -3

        log.info('Constructed {0} candidates'.format(len(ipdata)))
        if ARGS_write_pairs:
            nr_records = libtools.write_constructed_pairs(pathlib.Path(ARGS_base_dir) / ARGS_write_pairs, ipdata,
                                                          include_domain=include_domain)
            log.info('Wrote [{0}] IP candidate pairs to [{1}]'.format(nr_records, str(
                pathlib.Path(ARGS_base_dir) / ARGS_write_pairs)))
            log.info('Exiting now ...')
            return 0

        if ARGS_start_index or ARGS_end_index:  # slice if requested
            length = len(ipdata)
            if ARGS_end_index is None or ARGS_end_index > length:
                ARGS_end_index = length

            if ARGS_start_index >= ARGS_end_index:
                log.error(
                    'Start index can not be higher/equal than end index (start/end: {0} / {1})'.format(ARGS_start_index,
                                                                                                       ARGS_end_index))
                return -6
            elif ARGS_start_index > length:
                log.error(
                    'Start index is higher than the number of targets available (start index / data size: {0} / {1}'.format(
                        ARGS_start_index, length))
                return -6

            ipdata = ipdata[ARGS_start_index: ARGS_end_index]

            log.info(
                'Reduced targets from size [{0}] to [{1}] (indices from [{2}] to [{3}])'.format(length, len(ipdata),
                                                                                                ARGS_start_index,
                                                                                                ARGS_end_index))

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

                if ARGS_cdn_file:
                    if const.CDNFILTER.is_cdn(ip4, ip6):
                        CDN_FILTERED[(ip4, ip6)] = domains
                        if domains:
                            info_str = '({0} of {1}) Filtered target (CDN) {2} / {3} [{4}]'.format(n, ipdata_len, ip4,
                                                                                                   ip6, domains)
                        else:
                            info_str = '({0} of {1}) Filtered target (CDN) {2} / {3}'.format(n, ipdata_len, ip4, ip6)
                        log.info(info_str)
                        continue

                log.info(info_str)

                trace_set = libtrace.TraceSet(target=(ip4, ip6), domain=domains)
                key = str(ip4) + '_' + str(ip6)
                if key in TRACE_SETS:  # should never happen
                    log.error('Target {0} / {1} already in trace sets!'.format(ip4, ip6))
                    continue

                nr_current_traces = 0
                no_results_counter = 0  # if more than X traces have no active nodes continue with next target
                no_new_trace_counter = 0  # in case there are no new traces available to hit the requested number of traces

                while nr_current_traces < const.NR_TRACES_PER_TRACE_SET:
                    # -> libconstants.TRACEROUTE_ADD_SOURCE_IP (False)
                    ip4tracert, ip6tracert = libtraceroute.CPTraceroute((ip4, ip6), iface=nic, algorithm='traceroute',
                                                                        timeout=2).traceroute(result_timeout=3)

                    # check for CDN after very few hops
                    # if ARGS_cdn_file:
                    #   if len(ip4tracert) < const.CDN_HOP_THRESHOLD or len(ip6tracert) < const.CDN_HOP_THRESHOLD:
                    #     if const.CDNFILTER.is_cdn(ip4, ip6):
                    #       CDN_FILTERED[(ip4, ip6)] = domains
                    #       break # stop and do not inspect CDN target

                    try:
                        trace = libtrace.Trace().init(ip4, ip6, ip4tracert, ip6tracert, v4bl_re=v4bl_re,
                                                      v6bl_re=v6bl_re, iface=nic)
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
                        apply_ignore_regex=bool(ARGS_ip_ignore_file))  # only apply regex if ignore file was given

                    tsports = libts.TraceSetPortScan(nodes4, nodes6, port_list=const.PORT_LIST, iface=nic).start()
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

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise
        finally:
            ts_written = libtrace.write_trace_sets(ARGS_base_dir, TRACE_SETS)
            if const.WRITE_INACTIVE_TRACE_SET:
                ts_silent_written = libtrace.write_trace_sets(base_dir_silent, SILENT_TRACE_SETS)
                if ts_written > 0 or ts_silent_written > 0:
                    log.info('Active TraceSets written: {0} / Inactive TraceSets written: {1}'.format(ts_written,
                                                                                                      ts_silent_written))
            else:
                if ts_written > 0:
                    log.info('Active TraceSets written: {0}'.format(ts_written))

            filtered_cdns_written = cdnfilter.write_filtered(ARGS_base_dir, CDN_FILTERED, include_domain=include_domain)
            if filtered_cdns_written > 0:
                log.info('Filtered CDN pairs written: {0}'.format(filtered_cdns_written))

    ##########

    elif ARGS_candidates_available:  # elif ARGS_candidates_csv_file is not None:

        if ARGS_resolved:
            ports_available = False
            ts_data_available = False
            # keep in mind that slicing does not yield deterministic results if one_per_domain is True
            CANDIDATE_PAIRS = const.ALEXA.construct_candidates(
                one_per_domain=False)  # gives ~ 500k candidates for 145k resolved hosts of Alexa Top List
            if not CANDIDATE_PAIRS:
                if ARGS_resolved_file:
                    log.error('{0}: Empty file!'.format(ARGS_resolved_file))
                else:
                    log.error('Empty candidate pairs!')
                return -3
        else:
            log.info('Loading candidate file {0}'.format(ARGS_candidates_csv_file))
            # load candidate pairs
            ports_available, ts_data_available, tcp_opts_available, CANDIDATE_PAIRS = libts.load_candidate_pairs(
                ARGS_candidates_csv_file, v4bl_re=v4bl_re, v6bl_re=v6bl_re, include_domain=True)
            if not CANDIDATE_PAIRS:
                log.error('{0}: Empty file!'.format(ARGS_candidates_csv_file))
                return -3

        # Python 3.6+ preserves insertion order with built-in dict
        if ARGS_start_index or ARGS_end_index:  # slice data
            length = len(CANDIDATE_PAIRS)
            if ARGS_end_index is None or ARGS_end_index > length:
                ARGS_end_index = length

            if ARGS_start_index >= ARGS_end_index:
                log.error(
                    'Start index can not be higher/equal than end index (start/end: {0} / {1})'.format(ARGS_start_index,
                                                                                                       ARGS_end_index))
                return -6
            elif ARGS_start_index > length:
                log.error(
                    'Start index is higher than the number of CandidatePairs available (start index / data size: {0} / {1}'.format(
                        ARGS_start_index, length))
                return -6

            keys = list(CANDIDATE_PAIRS.keys())[ARGS_start_index: ARGS_end_index]
            CANDIDATE_PAIRS = {key: CANDIDATE_PAIRS[key] for key in keys}

            log.info('Reduced candidates from size [{0}] to [{1}] (indices from [{2}] to [{3}])'.format(length, len(
                CANDIDATE_PAIRS), ARGS_start_index, ARGS_end_index))

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
                if not ARGS_resolved:
                    log.info('No open ports available in candidate file')

                nodes4 = set()  # do not add IPs more than once
                nodes6 = set()
                for cp in CANDIDATE_PAIRS.values():
                    nodes4.add(cp.ip4)
                    nodes6.add(cp.ip6)

                log.info('Starting open port identification')

                cpscan = libts.CandidatePortScan(nodes4, nodes6, port_list=const.PORT_LIST, iface=nic).start()

                while not cpscan.finished():
                    # do not choose this value too high otherwise the function will never return because
                    # there always will be data available (queue.empty exception will never be raised)
                    cpscan.process_results(ip_cp_lut,
                                           timeout=1.5)  # 1.5 seconds seems to be the optimum for debug output
                cpscan.process_results(ip_cp_lut, timeout=3)  # was 5
                cpscan.stop()  # must be explicitly stopped!

                log.info('Finished with port identification')

        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            raise
        finally:
            # write responding candidate pairs to file (no timestamp data!)
            if not ports_available:
                nr_candidates_written, nr_data_records_written = libts.write_candidate_pairs(CANDIDATE_PAIRS,
                                                                                             ARGS_base_dir,
                                                                                             only_active_nodes=True,
                                                                                             write_candidates=True,
                                                                                             write_ts_data=False,
                                                                                             write_tcp_opts_data=True,
                                                                                             include_domain=True)

    ##########

    else:
        log.critical('Should never reach here ...')
        raise RuntimeError('Undefined program flow')

    ##########

    if not len(TRACE_SETS) > 0 and not ARGS_candidates_available:
        log.warning('No active nodes available!')
        return 0

    if ARGS_candidates_available:
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

    if ARGS_perform_harvesting and not ARGS_candidates_available:
        # only harvest if not already done
        if not any([ts.has_timestamp_data() for ts in TRACE_SETS.values()]):
            log.info('Starting harvesting task ...')

            try:
                harvester = libts.TraceSetHarvester(TRACE_SETS, runtime=const.HARVESTING_RUNTIME,
                                                    interval=const.HARVESTING_INTERVAL, iface=nic)
                control_thread = harvester.start()

                while not harvester.finished():
                    harvester.process_results(timeout=const.HARVESTING_RESULTS_TIMEOUT)
                harvester.process_results(timeout=const.HARVESTING_RESULTS_TIMEOUT_FINAL)

            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                raise
            finally:
                log.info('Total records processed: {0}'.format(harvester.total_records_processed()))

                log.info('Now writing harvesting data ...')
                # assumes trace sets already written to disk
                for tset in TRACE_SETS.values():
                    tset.write_timestamp_data(ARGS_base_dir)

                log.info('Finished writing timestamp data')

        else:
            log.warning('TraceData for TraceSets available. Harvesting will not be performed!')

    elif ARGS_perform_harvesting and ARGS_candidates_available:
        if not ts_data_available:
            log.info('Starting harvesting task ...')

            try:
                harvester = libts.CandidateHarvester(CANDIDATE_PAIRS, runtime=const.HARVESTING_RUNTIME,
                                                     interval=const.HARVESTING_INTERVAL, iface=nic)
                harvester.start()

                while not harvester.finished():
                    harvester.process_results(timeout=const.HARVESTING_RESULTS_TIMEOUT)
                harvester.process_results(timeout=const.HARVESTING_RESULTS_TIMEOUT_FINAL)

            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception:
                raise
            finally:
                log.info('Total records processed: {0}'.format(harvester.total_records_processed()))
                log.info('Now writing harvesting data ...')

                nr_candidates_written, nr_data_records_written = libts.write_candidate_pairs(CANDIDATE_PAIRS,
                                                                                             ARGS_base_dir,
                                                                                             write_candidates=False,
                                                                                             write_ts_data=True,
                                                                                             write_tcp_opts_data=False,
                                                                                             include_domain=True)

                if nr_data_records_written > 0:
                    ts_data_available = True  # now we have timestamp data available

        else:
            # do not harvest if timestamp data was loaded, instead print a warning
            tsfile = str(os.path.join(os.path.dirname(ARGS_candidates_csv_file), const.CANDIDATE_PAIRS_DATA_FILE_NAME))
            log.warning('Timestamps already loaded from [{0}]'.format(tsfile))
            log.warning('Harvesting will not be performed!')

    ##########

    # stop here if no evaluation was requested
    if ARGS_no_evaluation:
        log.warning('No evaluation requested (--no-evaluation). Exiting.')
        return 0

    # stop here if only portscan was requested
    if (ARGS_candidates_available and ts_data_available) or any(
            [ts.has_timestamp_data() for ts in TRACE_SETS.values()]):
        candidates = None
        if ARGS_candidates_available:
            candidates = libsiblings.construct_node_candidates(CANDIDATE_PAIRS, low_runtime=ARGS_lowruntime)
        else:
            candidates = libsiblings.construct_trace_candidates(TRACE_SETS, low_runtime=ARGS_lowruntime)

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
    if not ARGS_no_ssh_keyscan:
        log.info('Preparing ssh-keyscan ...')
        sshkeyscan = keyscan.Keyscan(candidates, directory=ARGS_base_dir, timeout=None,
                                     key_file_name=const.SSH_KEYS_FILENAME, agent_file_name=const.SSH_AGENTS_FILENAME,
                                     keyscan_command=const.SSH_KEYSCAN_COMMAND)
        if not sshkeyscan.has_keys():  # assign available keys to candidates
            log.info('No keyfile found, starting ssh-keyscan processes')
            done = sshkeyscan.run(write_keyfile=True, split_output=False)  # if not available, run ssh-keyscan
            if not done:
                log.warning('No nodes to scan for SSH keys ...')
            else:
                log.info('Finished ssh-keyscan')
        else:
            log.info('Loaded ssh keys from file [{0}]'.format(pathlib.Path(ARGS_base_dir, const.SSH_KEYS_FILENAME)))
    else:
        log.info('No ssh-keyscan requested')

    # stop here if solely ssh-keyscan was requested
    if ARGS_only_ssh_keyscan:
        log.info('--only-ssh-keyscan requested, exiting now ...')
        return 0

    ##### EVALUATE #####
    log.info('Calculations for evaluation started ...')
    for c in candidates.values():
        try:
            c.evaluate()
        except Exception as e:
            exc_type, exc_object, exc_traceback = sys.exc_info()
            ef = traceback.extract_tb(exc_traceback)[-1]  # get the inner most error frame
            string = '{0} in {1} (function: \'{2}\') at line {3}: "{4}" <{5}>'.format(exc_type.__name__,
                                                                                      os.path.basename(ef.filename),
                                                                                      ef.name, ef.lineno, str(e),
                                                                                      ef.line)

    log.info('Finished sibling candidate calculations')

    ##### OUTFILE #####
    if ARGS_resultfile:
        resultfile = pathlib.Path(ARGS_resultfile)
        if not resultfile.is_absolute():
            resultfile = const.BASE_DIRECTORY / resultfile
        log.info('Writing resultfile [{0}] ...'.format(resultfile))
        nr_records = libsiblings.write_results(candidates.values(), resultfile, low_runtime=ARGS_lowruntime)
        log.info('Wrote {0} result records to file'.format(nr_records))

    ##### PLOT #####
    if ARGS_print:  # plots all candidates to base_directory/const.PLOT_FILE_NAME
        log.info('Starting plot process ...')
        libsiblings.plot_all(candidates.values(), const.PLOT_FILE_NAME)
        log.info('Finished printing charts')

    if not ARGS_resultfile and not ARGS_print:
        log.info('Nothing more to do ... Exiting ...')

    return 0

    ##################
    #### TESTING #####
    ##################

    index = random.randrange(0, len(
        candidates))  # 0, 22, 177[very high raw tcp ts diff] (1k hz), 95 (250 hz) to test, 6 (ranodmized ts)
    c = list(candidates.values())[index]
    print('index: {0} - {1}'.format(index, c))
    is_sibling = c.evaluate()
    print('evaluate: {0}'.format(is_sibling))
    print('status: {0}'.format(c.sibling_status))

    if not is_sibling:
        print('error')
    else:
        # print('took {0} candidates'.format(counter))
        print('hertz:', c.hz4, c.hz6)
        print('hertz raw:', c.hz4_raw, c.hz6_raw)
        print('R-squared:', c.hz4_R2, c.hz6_R2)
        print('raw_ts_diff', c.raw_timestamp_diff)
        # print('Xi\n', c.Xi4, '\n', c.Xi6)
        # print('Vi\n', c.Vi4, '\n', c.Vi6)
        # print('time_offsets4\n', c.time_offsets4)
        # print()
        # print('time_offsets6\n', c.time_offsets6)
        # print('denoised4\n', c.denoised4)
        # print('denoised6\n', c.denoised6)
        # print('cleaned_mean4', c.cleaned_mean4)
        # print('cleaned_mean6', c.cleaned_mean6)
        # print('ppd_range_raw', c.ppd_range_raw)
        # print('ppd_index6_arr', c.ppd_index6_arr)
        # print('ppd_arr', c.ppd_arr)
        # print('ppd_mean_threshold', c.ppd_mean_threshold)
        # print('ppd_median_threshold', c.ppd_median_threshold)
        # print('ppd_arr_pruned', c.ppd_arr_pruned)
        # print('ppd_range_pruned', c.ppd_range_pruned)
        # print('alpha4', c.alpha4)
        # print('alpha6', c.alpha6)
        print('alphadiff', c.alphadiff)
        # print('rsqr4', c.rsqr4)
        # print('rsqr6', c.rsqr6)
        print('rsqrdiff', c.rsqrdiff)
        print('theta', c.theta)
        print('dynrange4', c.dynrange4)
        print('dynrange6', c.dynrange6)
        print('dynrange_diff', c.dynrange_diff)
        print('dynrange_diff_rel', c.dynrange_diff_rel)
        print('len spline4, xs4', len(c.spline_arr4), len(c.xs4))  # different sizes are possible
        print('len spline6, xs6', len(c.spline_arr6), len(c.xs6))  # for v4/v6
        # print('spline_arr4', c.spline_arr4)
        # print('spline_arr6', c.spline_arr6)
        # print('xs4', c.xs4)
        # print('xs6', c.xs6)
        # print('spl_mapped_diff', c.spl_mapped_diff)
        print('spl_mean4', c.spl_mean4)
        print('spl_mean6', c.spl_mean6)
        print('spl_mean_diff', c.spl_mean_diff)
        print('spl_percent_val', c.spl_percent_val)

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
        if const.ALEXA:  # only write file if data was modified
            if error:  # prevent overwriting probably existing files by using a different file name in case of error
                resolved_fname = os.path.join(const.BASE_DIRECTORY, const.ALEXA_RESOLVED_FILENAME_ERRORCASE)
                unresolvable_fname = os.path.join(const.BASE_DIRECTORY, const.ALEXA_UNRESOLVABLE_FILENAME_ERRORCASE)
            else:
                resolved_fname = os.path.join(const.BASE_DIRECTORY, const.ALEXA_RESOLVED_FILE_NAME)
                unresolvable_fname = os.path.join(const.BASE_DIRECTORY, const.ALEXA_UNRESOLVABLE_FILE_NAME)

            const.ALEXA.save_resolved(resolved_fname)
            const.ALEXA.save_unresolvable(unresolvable_fname)

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
