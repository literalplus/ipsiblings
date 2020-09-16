import argparse
import textwrap
from datetime import datetime

from .. import libconstants


def _prepare_parser():
    # noinspection PyTypeChecker
    created_parser = argparse.ArgumentParser(
        description=textwrap.dedent('IP Siblings Toolset')
    )

    path_grp = created_parser.add_argument_group(title='Paths', description=None)
    path_grp.add_argument(
        '-d', '--base-dir', help='Base directory for application data', default='./target'
    )
    path_grp.add_argument(
        '-i', '--ignore-ips-from', help='File of IP addresses to ignore for all operations'
    )
    path_grp.add_argument(
        '--eval-results-to', help='Write evaluation results to file', nargs='?', const=libconstants.RESULT_FILE_NAME
    )
    path_grp.add_argument(
        '--candidates-to', help='Write generated sibling candidates to a file'
    )
    path_grp.add_argument(
        '--run-id',
        help='Identifier for the run to contribute to, appended to the base directory. Generated if not given.',
        default=datetime.now().strftime("run_%Y-%M-%dT%H_%m_%S")
    )

    eval_grp = created_parser.add_argument_group(title='Evaluation', description=None)
    eval_grp.add_argument(
        '--low-runtime', action='store_true', help='Use low-runtime evaluation methods', default=False
    )
    eval_grp.add_argument(
        '--export-plots', action='store_true', help='Export plots after evaluation', default=False
    )

    skip_grp = created_parser.add_argument_group(title='Skip steps', description=None)
    skip_grp.add_argument(
        '--skip-eval', action='store_true',
        help='Skip any interpretation of collected data', default=False
    )
    skip_grp.add_argument(
        '--only-init', action='store_true',
        help='Exit after loading configuration', default=False
    )
    skip_grp.add_argument(
        '--no-ssh-keyscan', action='store_true', help='Do not scan for SSH host keys', default=False
    )
    skip_grp.add_argument(
        '--only-ssh-keyscan', action='store_true', help='Exit after keyscan', default=False
    )

    log_grp = created_parser.add_argument_group(title='Logging', description=None)
    logmutualgrp = log_grp.add_mutually_exclusive_group()
    logmutualgrp.add_argument('-v', '--verbose', action='count', help='Increase verbosity once per call', default=0)
    logmutualgrp.add_argument('-q', '--quiet', action='count', help='Decrease verbosity once per call', default=0)

    target_grp = created_parser.add_argument_group(title='Target nodes', description=None)
    target_grp.add_argument(
        '--targets-from', action='store', help='Where to get target nodes from',
        choices=['bitcoin', 'filesystem'], default='bitcoin'  # choices relate to preparation.provider.all
    )
    target_grp.add_argument(
        '--from', type=int, dest='start_index', help='Index of first target to consider'
    )
    target_grp.add_argument(
        '--to', type=int, dest='end_index', help='Index of first target to skip'
    )
    harvest_grp = created_parser.add_argument_group(title='Timestamp Collection', description=None)
    harvest_grp.add_argument(
        '--do-harvest', action='store_true', help='Do collect (harvest) timestamps if not present', default=False
    )
    harvest_grp.add_argument(
        '-ht', '--harvest-time', help='Collection duration, seconds',
        default=libconstants.HARVESTING_RUNTIME
    )
    harvest_grp.add_argument(
        '-hi', '--harvest-interval', help='Collection interval for a single node, seconds',
        default=libconstants.HARVESTING_INTERVAL
    )
    harvest_grp.add_argument(
        '-htr', '--harvest-timeout',
        help='Wait at least this many seconds for timestamp replies per iteration '
             '(Should not be too long so that the next run can start in time)',
        default=libconstants.HARVESTING_RESULTS_TIMEOUT
    )
    harvest_grp.add_argument(
        '-htf', '--harvest-timeout-final',
        help='Wait at least this long for timestamp replies after the last iteration',
        default=libconstants.HARVESTING_RESULTS_TIMEOUT_FINAL
    )

    return created_parser


parser = _prepare_parser()
