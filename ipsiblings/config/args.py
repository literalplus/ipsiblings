import argparse
import os
import sys
import textwrap

from .. import libconstants


def _prepare_parser():
    # noinspection PyTypeChecker
    created_parser = argparse.ArgumentParser(
        description=textwrap.dedent('''\
            IP Siblings Toolset
    
            The argument of -c/-t option (combined with -s option) can be used with alexa
            top list file if resolution is required.
            [Any other file formatted in that way can be used.]'''),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )

    one_grp = created_parser.add_argument_group(title='required argument, exactly one', description=None)
    mutualgrp = one_grp.add_mutually_exclusive_group(required=True)
    mutualgrp.add_argument('-c', '--candidates', action='store',
                           help='parse candidates from csv file or top list (-s)',
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
    mutualgrp.add_argument('--debug', action='store_true', help='debug run (only run initialization)',
                           default=False)

    opt_grp = created_parser.add_argument_group(title='optional arguments', description=None)
    opt_grp.add_argument('-h', '--help', action='help', help='show this help message and exit')
    opt_grp.add_argument('-d', '--directory', action='store', help='base directory to store and load trace sets',
                         default=None)
    opt_grp.add_argument('-i', '--ignore-file', action='store', help='nodes to ignore are listed in this file',
                         default=None)
    opt_grp.add_argument('-r', '--run-harvest', action='store_true', help='perform harvesting for candidate IPs',
                         default=False)
    opt_grp.add_argument('-s', '--resolved', action='store_true',
                         help='construct candidates or trace targets from resolved (alexa top) list '
                              '(use with -c/-t for operation mode)',
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
                         nargs='?', const=libconstants.RESULT_FILE_NAME)
    opt_grp.add_argument('--no-evaluation', action='store_true',
                         help='do not perform any calculations/evaluations on sibling candidates', default=False)
    opt_grp.add_argument('--cdn-file', action='store', help='load CDN networks for IP filtering', default=None)
    opt_grp.add_argument('--write-pairs', action='store', help='write constructed IP pairs to file', default=None,
                         nargs='?', const=libconstants.IP_PAIRS_FILE_NAME)
    opt_grp.add_argument('--no-ssh-keyscan', action='store_true', help='do not scan for public ssh keys',
                         default=False)
    opt_grp.add_argument('--only-ssh-keyscan', action='store_true', help='exit after keyscan', default=False)

    log_grp = created_parser.add_argument_group(title='optional logging arguments', description=None)
    logmutualgrp = log_grp.add_mutually_exclusive_group()
    logmutualgrp.add_argument('-v', '--verbose', action='count', help='increase verbosity once per call', default=0)
    logmutualgrp.add_argument('-q', '--quiet', action='count', help='decrease verbosity once per call', default=0)

    geo_grp = created_parser.add_argument_group(title='optional geolocation arguments', description=None)
    geo_grp.add_argument('--city-db', action='store', help='custom MaxMind city database', default=None)
    geo_grp.add_argument('--asn-db', action='store', help='custom MaxMind ASN database', default=None)
    geo_grp.add_argument('--update-geo-dbs', action='store_true', help='update geolocation databases',
                         default=False)
    return created_parser


def print_usage_and_exit(message):
    parser.print_usage(sys.stderr)
    basename = os.path.basename(sys.argv[0])
    sys.stderr.write(f'{basename}: error: {message}\n')
    sys.exit(2)


parser = _prepare_parser()
