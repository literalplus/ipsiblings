from .harvester import Harvester
from .. import liblog
from ..config import HarvesterConfig, AppConfig
from ..model import PreparedTargets, NicInfo

log = liblog.get_root_logger()


def _provide_harvester_for(nic: NicInfo, conf: HarvesterConfig, prepared_targets: PreparedTargets) -> Harvester:
    return Harvester(nic, conf, prepared_targets)


def run(prepared_targets: PreparedTargets, conf: AppConfig, nic: NicInfo):
    if conf.flags.do_harvest:
        if prepared_targets.has_timestamps() and not conf.flags.always_harvest:
            log.warning(f'Not harvesting, it was already done - {prepared_targets.kind}')
            return
        log.info('Starting harvesting task ...')
        harvester = _provide_harvester_for(nic, conf.harvester, prepared_targets)
        try:
            harvester.start()
            while not harvester.finished():
                harvester.process_results_running()
            harvester.process_results_final()
        finally:
            log.info(f'Total records processed: {harvester.total_records_processed()}')
            prepared_targets.notify_timestamps_added()
    else:
        log.info(f'No harvesting requested, exporting targets without timestamps.')
