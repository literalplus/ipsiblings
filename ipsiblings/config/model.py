import os
from enum import Enum
from typing import Set, Type, TypeVar, List

from .args import parser
from .. import liblog
from ..model import const

T = TypeVar('T', bound=Enum)


def _convert_enum(kind: Type[T], key: str) -> T:
    # Validation should be done by choices= passed to argparse
    clean_key = key.upper().replace('-', '_')
    return kind[clean_key]


class PathsConfig:
    def __init__(self, args):
        self.base_dir = os.path.join(args.base_dir, args.run_id)
        self.candidates_out = 'candidates.tsv'


class CandidatesConfig:
    def __init__(self, args):
        self.low_runtime = args.low_runtime


class TargetProviderConfig:
    def __init__(self, args):
        self.provider = _convert_enum(const.TargetProviderChoice, args.targets_from)
        self.skip_ip_versions: Set[int] = set(args.skip_v)


class FlagsConfig:
    def __init__(self, args):
        self.do_harvest = args.do_harvest
        self.always_harvest = args.really_harvest
        self.only_init = args.only_init


class EvalConfig:
    def __init__(self, args):
        self.evaluators: List[const.EvaluatorChoice] = [
            _convert_enum(const.EvaluatorChoice, key)
            for key in args.evaluator
            if key not in args.skip_evaluator
        ]
        self.export_plots = args.export_plots
        self.skip = args.skip_eval
        self.batch_size = args.eval_batch_size
        self.fail_fast = args.eval_fail_fast
        self.ssh_timeout = args.eval_ssh_timeout
        self.first_batch_idx = args.eval_first_batch
        self.batch_count = args.eval_batch_count


class HarvesterConfig:
    def __init__(self, args):
        self.runtime = args.harvest_duration
        self.ts_interval = args.ts_interval
        self.btc_interval = args.btc_interval
        self.ts_running_timeout = args.ts_timeout
        self.final_timeout = args.harvest_timeout_final
        if not args.harvester:
            args.harvester = const.HarvesterChoice.all_keys()
        self.harvesters: List[const.HarvesterChoice] = [
            _convert_enum(const.HarvesterChoice, key)
            for key in args.harvester
        ]


class OsTunerConfig:
    def __init__(self, args):
        self.skip_sysctls = args.skip_os_sysctls
        self.skip_firewall = args.skip_os_iptables
        self.skip_timesync = args.skip_os_ntp


class AppConfig:
    """
    Main entry point for accessing the configuration.
    """

    def __init__(self):
        self.args = parser.parse_args()
        self.run_id = self.args.run_id
        self.paths = PathsConfig(self.args)
        self.flags = FlagsConfig(self.args)
        self.targetprovider = TargetProviderConfig(self.args)
        self.candidates = CandidatesConfig(self.args)
        self.harvester = HarvesterConfig(self.args)
        self.os_tuner = OsTunerConfig(self.args)
        self.eval = EvalConfig(self.args)

        # start_index, end_index to restrict amount of data to process
        self.start_index = self.args.start_index
        self.end_index = self.args.end_index
        if self.start_index is None:
            self.start_index = 0
        self.verbosity = self.args.verbose - self.args.quiet

    @property
    def base_dir(self):
        return os.path.join(self.paths.base_dir)

    @property
    def log_level(self):
        if self.verbosity <= -2:
            return liblog.CRITICAL
        elif self.verbosity <= -1:
            return liblog.ERROR
        elif self.verbosity == 0:  # the default
            return liblog.WARNING
        elif self.verbosity == 1:
            return liblog.INFO
        else:
            return liblog.DEBUG
