import os

from .args import parser
from .. import liblog


class PathsConfig:
    def __init__(self, args):
        self.base_dir = os.path.join(args.base_dir, args.run_id)
        self.ip_ignores = args.ignore_ips_from
        self.eval_out = args.eval_results_to
        self.candidates_out = args.candidates_to


class CandidatesConfig:
    def __init__(self, args):
        self.low_runtime = args.low_runtime
        self.skip_keyscan = args.no_ssh_keyscan
        self.only_keyscan = args.only_ssh_keyscan
        self.skip_evaluation = args.skip_eval


class TargetProviderConfig:
    def __init__(self, args):
        self.provider = args.targets_from


class FlagsConfig:
    def __init__(self, args):
        self.do_harvest = args.do_harvest
        self.always_harvest = args.really_harvest
        self.export_plots = args.export_plots
        self.only_init = args.only_init
        self.skip_evaluation = args.skip_eval


class HarvesterConfig:
    def __init__(self, args):
        self.runtime = args.harvest_time
        self.interval = args.harvest_interval
        # timeout during the run
        self.running_timeout = args.harvest_timeout
        # timeout in the final collection stage
        self.final_timeout = args.harvest_timeout_final


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
