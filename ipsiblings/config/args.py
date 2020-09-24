import argparse
import textwrap
from datetime import datetime

from .. import libconstants


def _prepare_parser():
    # noinspection PyTypeChecker
    created_parser = argparse.ArgumentParser(
        description=textwrap.dedent('IP Siblings Toolset')
    )

    path_grp = created_parser.add_argument_group(title='PATHS', description=None)
    path_grp.add_argument(
        '-d', '--base-dir', help='Base directory for application data (default ./target)', default='./target'
    )
    path_grp.add_argument(
        '--ignore-ips-from', help='File of IP addresses to ignore for all operations'
    )
    path_grp.add_argument(
        '--eval-results-to', help='Write evaluation results to file', nargs='?', const=libconstants.RESULT_FILE_NAME
    )
    path_grp.add_argument(
        '--candidates-to', help='Write generated sibling candidates to a file'
    )
    path_grp.add_argument(
        '--run-id',
        help='Identifier for the run to contribute to, appended to the base directory. (default current date-time)',
        default=datetime.now().strftime("run_%Y-%m-%dT%H_%M_%S")
    )

    eval_grp = created_parser.add_argument_group(title='EVALUATION', description=None)
    eval_grp.add_argument(
        '--low-runtime', action='store_true', help='Use low-runtime evaluation methods', default=False
    )
    eval_grp.add_argument(
        '--export-plots', action='store_true', help='Export plots after evaluation', default=False
    )

    skip_grp = created_parser.add_argument_group(title='SKIP STEPS', description=None)
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

    log_grp = created_parser.add_argument_group(title='LOGGING', description=None)
    logmutualgrp = log_grp.add_mutually_exclusive_group()
    logmutualgrp.add_argument('-v', '--verbose', action='count', help='Increase verbosity once per call', default=0)
    logmutualgrp.add_argument('-q', '--quiet', action='count', help='Decrease verbosity once per call', default=0)

    target_grp = created_parser.add_argument_group(title='TARGET NODES', description=None)
    target_grp.add_argument(
        '--targets-from', action='store', help='Where to get target nodes from (default bitcoin)',
        choices=['bitcoin', 'filesystem'], default='bitcoin'  # choices relate to preparation.provider.all
    )
    target_grp.add_argument(
        '--skip-v', type=int, action='append', default=[],
        help='Skip IPvX addresses while acquiring targets '
             '(for testing only, may be specified multiple times, ignored for filesystem provider)'
    )
    target_grp.add_argument(
        '--from', type=int, dest='start_index', help='Index of first target to consider (default 0)'
    )
    target_grp.add_argument(
        '--to', type=int, dest='end_index', help='Index of first target to skip (default none)'
    )
    harvest_grp = created_parser.add_argument_group(title='TIMESTAMP COLLECTION', description=None)
    harvest_grp.add_argument(
        '--do-harvest', action='store_true', help='Collect (harvest) timestamps if not present', default=False
    )
    harvest_grp.add_argument(
        '--really-harvest', action='store_true', help='Harvest even if we already have timestamps', default=False
    )
    harvest_grp.add_argument(
        '-ht', '--harvest-time', type=int,
        help=f'Collection duration, seconds (default {libconstants.HARVESTING_RUNTIME})',
        default=libconstants.HARVESTING_RUNTIME
    )
    harvest_grp.add_argument(
        '-hi', '--harvest-interval', type=int,
        help=f'Collection interval for a single node, seconds  (default {libconstants.HARVESTING_INTERVAL})',
        default=libconstants.HARVESTING_INTERVAL
    )
    harvest_grp.add_argument(
        '-htr', '--harvest-timeout', type=int,
        help='Wait at least this many seconds for timestamp replies per iteration '
             '(Should not be too long so that the next run can start in time) '
             f'(default {libconstants.HARVESTING_RESULTS_TIMEOUT})',
        default=libconstants.HARVESTING_RESULTS_TIMEOUT
    )
    harvest_grp.add_argument(
        '-htf', '--harvest-timeout-final', type=int,
        help='Wait at least this long for timestamp replies after the last iteration '
             f'(default {libconstants.HARVESTING_RESULTS_TIMEOUT_FINAL})',
        default=libconstants.HARVESTING_RESULTS_TIMEOUT_FINAL
    )

    os_grp = created_parser.add_argument_group(
        title='OPERATING SYSTEM SETTINGS',
        description='By default, we adapt some global (!!) OS settings. '
                    'The previous values are saved to ./settings.bak and restored when the application exits.'
    )
    os_grp.add_argument(
        '--skip-os-sysctls', action='store_true',
        help='Skip overwriting necessary sysctls', default=False
    )
    os_grp.add_argument(
        '--skip-os-iptables', action='store_true',
        help='Skip adding necessary iptables rules', default=False
    )
    os_grp.add_argument(
        '--skip-os-ntp', action='store_true',
        help='Skip disabling NTP client', default=False
    )

    return created_parser


parser = _prepare_parser()
