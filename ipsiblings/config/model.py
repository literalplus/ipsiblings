import os
import time

from .args import parser
from .. import libconstants
from .. import liblog


class PathsConfig:
    def __init__(self, args):
        # base directory where data will be read from or written to
        if args.directory:
            self.base_dir = os.path.join(args.directory, '')
        else:
            self.base_dir = os.path.join(libconstants.BASE_DIRECTORY, time.strftime("%Y-%m-%d_%H.%M.%S"))
        # trace sets without answering nodes will be written to this directory
        self.base_dir_silent = os.path.join(self.base_dir, libconstants.DIRECTORY_SILENT_NODES, '')
        self.ip_ignores = args.ignore_file
        # trace targets csv file
        self.target_csv = args.trace_targets
        self.cdns = args.cdn_file


class PortScanConfig:
    def __init__(self, args):
        self.router_portlist = args.router_ports
        self.server_portlist = args.server_ports


class CandidatesConfig:
    def __init__(self, args):
        # examine nodes given in candidate csv file
        self.in_csv = args.candidates
        self.out_csv = args.resultfile
        # determine if we deal with concrete (submitted) nodes or trace sets containing candidate nodes
        # evaluate to true if no additional argument for -c/-t is given
        self.available = bool(self.in_csv)
        self.low_runtime = args.low_runtime
        self.skip_keyscan = args.no_ssh_keyscan
        self.only_keyscan = args.only_ssh_keyscan
        # If set, candidate pairs will be saved but nothing else will happen
        self.just_write_pairs_to = args.write_pairs


class GeoipConfig:
    def __init__(self, args):
        self.city_db = args.city_db
        self.asn_db = args.asn_db
        self.do_update = args.update_geo_dbs


class TraceSetConfig:
    def __init__(self, args):
        # True: load trace set data from base directory; False: run active node discovery with given csv file
        self.do_load = args.load


class TargetProviderConfig:
    def __init__(self, args):
        self.provider = args.target_provider
        self.toplist_dir = args.alexa_toplist_dir
        self.resolved_ips_path = args.resolved_file
        self.has_resolved = args.resolved
        self.do_download = args.download_alexa


class FlagsConfig:
    def __init__(self, args, paths: PathsConfig):
        # True: perform harvesting task for the identified trace sets or the loaded candidates
        self.do_harvest = args.run_harvest
        # this allows us to distinguish whether candidate or target tasks should be performed
        self.has_targets = bool(paths.target_csv)
        self.do_print = args.print


class HarvesterConfig:
    def __init__(self):
        self.runtime = libconstants.HARVESTING_RUNTIME
        self.interval = libconstants.HARVESTING_INTERVAL
        # timeout during the run
        self.running_timeout = libconstants.HARVESTING_RESULTS_TIMEOUT
        # timeout in the final collection stage
        self.final_timeout = libconstants.HARVESTING_RESULTS_TIMEOUT_FINAL


class AppConfig:
    def __init__(self):
        self.args = parser.parse_args()
        self.paths = PathsConfig(self.args)
        self.flags = FlagsConfig(self.args, self.paths)
        self.targetprovider = TargetProviderConfig(self.args)
        self.candidates = CandidatesConfig(self.args)
        self.geoip = GeoipConfig(self.args)
        self.trace_set = TraceSetConfig(self.args)
        self.port_scan = PortScanConfig(self.args)
        self.harvester = HarvesterConfig()

        # start_index, end_index to restrict amount of data to process
        self.start_index = self.args.start_index
        self.end_index = self.args.end_index
        if self.start_index is None:
            self.start_index = 0
        self.verbosity = self.args.verbose - self.args.quiet
        # run initialization only for debugging reasons
        self.debug = self.args.debug
        self.skip_evaluation = self.args.no_evaluation

    @property
    def base_dir(self):
        return self.paths.base_dir

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
