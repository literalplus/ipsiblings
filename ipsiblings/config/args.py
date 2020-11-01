import argparse
import textwrap
from datetime import datetime

from .. import libconstants
from ..model import const


def _prepare_parser():
    created_parser = argparse.ArgumentParser(
        description=textwrap.dedent('IP Siblings Toolset')
    )

    path_grp = created_parser.add_argument_group(title='PATHS', description=None)
    path_grp.add_argument(
        '-d', '--base-dir', help='Base directory for application data (default ./target)', default='./target'
    )
    path_grp.add_argument(
        '--run-id',
        help='Identifier for the run to contribute to, appended to the base directory. (default current date-time)',
        default=datetime.now().strftime("run_%Y-%m-%dT%H_%M_%S")
    )

    eval_grp = created_parser.add_argument_group(title='EVALUATION', description=None)
    eval_grp.add_argument(
        '--export-plots', action='store_true', help='Export plots after evaluation', default=False
    )
    eval_grp.add_argument(
        '--evaluator', action='append',
        help='Select a specific evaluator instead of running all of them. '
             'May be specified multiple times.',
        choices=const.EvaluatorChoice.all_keys(), default=[]
    )
    eval_grp.add_argument(
        '--skip-evaluator', action='append',
        help='Skip a specific evaluator. '
             'May be specified multiple times.',
        choices=const.EvaluatorChoice.all_keys(), default=[]
    )
    eval_grp.add_argument(
        '--eval-batch-size', help='Candidates to evaluate per batch (default 10_000)',
        default=30_000, type=int
    )
    eval_grp.add_argument(
        '--eval-fail-fast', help='Exit immediately upon the first evaluation exception.',
        action='store_true', default=False
    )
    eval_grp.add_argument(
        '--eval-ssh-timeout', help='Timeout in seconds per batch for SSH keyscan, default 60.',
        default=60, type=int
    )
    eval_grp.add_argument(
        '--eval-first-batch', help='Start counting eval batches at this number, default 0.',
        default=0, type=int
    )
    eval_grp.add_argument(
        '--eval-batch-count', help='How many batches to evaluate, default all.',
        default=-1, type=int
    )
    eval_grp.add_argument(
        '--eval-discard-results', help='Discard evaluation results (to only invoke side effects, e.g. keyscan)',
        action='store_true', default=False
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

    log_grp = created_parser.add_argument_group(title='LOGGING', description=None)
    logmutualgrp = log_grp.add_mutually_exclusive_group()
    logmutualgrp.add_argument('-v', '--verbose', action='count', help='Increase verbosity once per call', default=0)
    logmutualgrp.add_argument('-q', '--quiet', action='count', help='Decrease verbosity once per call', default=0)

    target_grp = created_parser.add_argument_group(title='TARGET NODES', description=None)
    default_target_provider = const.TargetProviderChoice.default()
    target_grp.add_argument(
        '--targets-from', action='store', help=f'Where to get target nodes from (default {default_target_provider})',
        choices=const.TargetProviderChoice.all_keys(), default=default_target_provider.name
    )
    target_grp.add_argument(
        '--skip-v', type=int, action='append', default=[],
        help='Skip IPvX addresses while acquiring targets '
             '(for testing, may be specified multiple times, ignored for filesystem provider)'
    )
    target_grp.add_argument(
        '--from', type=int, dest='start_index', help='Index of first target to consider (default 0)'
    )
    target_grp.add_argument(
        '--to', type=int, dest='end_index', help='Index of first target to skip (default none)'
    )

    harvest_grp = created_parser.add_argument_group(title='TIMESTAMP COLLECTION', description=None)
    harvest_grp.add_argument(
        '--do-harvest', action='store_true', help='Collect (harvest) if no timestamps present', default=False
    )
    harvest_grp.add_argument(
        '--really-harvest', action='store_true', help='Harvest even if we already have timestamps', default=False
    )
    harvest_grp.add_argument(
        '--harvester', action='append',
        help='Select a specific harvester instead of running all of them. '
             'May be specified multiple times.',
        choices=const.HarvesterChoice.all_keys(), default=[]
    )
    harvest_grp.add_argument(
        '-hd', '--harvest-duration', type=int,
        help=f'Collection duration, seconds (default {libconstants.HARVESTING_RUNTIME})',
        default=libconstants.HARVESTING_RUNTIME
    )
    harvest_grp.add_argument(
        '-ti', '--ts-interval', type=int,
        help=f'Collection interval for timestamps per target, seconds (default {libconstants.HARVESTING_INTERVAL})',
        default=libconstants.HARVESTING_INTERVAL
    )
    harvest_grp.add_argument(
        '-bi', '--btc-interval', type=int,
        help=f'Collection interval for Bitcoin protocol per target, seconds (default 1800 / 30min)',
        default=1800
    )
    harvest_grp.add_argument(
        '-htf', '--harvest-timeout-final', type=int,
        help='Wait at least this long for replies after the last iteration '
             f'(default {libconstants.HARVESTING_RESULTS_TIMEOUT_FINAL})',
        default=libconstants.HARVESTING_RESULTS_TIMEOUT_FINAL
    )

    os_grp = created_parser.add_argument_group(
        title='OPERATING SYSTEM SETTINGS',
        description='By default, we adapt some global (!!) OS settings. '
                    'The previous values are saved to ./settings.bak and restored when the application exits.'
    )
    os_grp.add_argument(
        '--skip-os', action='store_true',
        help='Skip all OS settings', default=False
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
