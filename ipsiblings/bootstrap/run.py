import gc
from typing import Dict, Tuple

from .wiring import Wiring
from .. import liblog, preparation, config, libsiblings
from ..config import HarvesterConfig
from ..harvesting.harvester import Harvester
from ..libtools import NicInfo
from ..model import SiblingCandidate, PreparedTargets, JustExit, DataException
from ..preparation.serialization import TargetSerialization

"""
Runs the actual business logic of the application, calling high-level API methods of other modules.
"""

log = liblog.get_root_logger()


def _provide_harvester_for(nic: NicInfo, conf: HarvesterConfig, prepared_targets: PreparedTargets) -> Harvester:
    return Harvester(nic, conf, prepared_targets)


def _perform_harvesting(prepared_targets: PreparedTargets, wiring: Wiring):
    conf = wiring.conf
    if conf.flags.do_harvest:
        if prepared_targets.has_timestamps():
            log.warning(f'Not harvesting, it was already done - {prepared_targets.kind}')
            return
        log.info('Starting harvesting task ...')
        harvester = _provide_harvester_for(wiring.nic, wiring.conf.harvester, prepared_targets)
        try:
            harvester.start()
            while not harvester.finished():
                harvester.process_results_running()
            harvester.process_results_final()
        finally:
            log.info(f'Total records processed: {harvester.total_records_processed()}')
            log.info('Now writing obtained timestamps ...')
            prepared_targets.notify_timestamps_added()
            TargetSerialization.export_targets(prepared_targets, conf.base_dir)
            log.info('Finished writing obtained timestamps.')


def _prepare_evaluation(prepared_targets: PreparedTargets, conf: config.AppConfig) -> Dict[Tuple, SiblingCandidate]:
    if conf.flags.skip_evaluation:
        log.warning('No evaluation requested (--no-evaluation). Exiting.')
        raise JustExit
    if not prepared_targets.has_timestamps():
        raise DataException('No timestamps available, was only a port scan requested?')
    candidates = libsiblings.construct_candidates_for(prepared_targets, conf)
    if not candidates:
        raise DataException('No sibling candidates available')
    log.info(f'Constructed {len(candidates)} sibling candidates')
    return candidates


def run(wiring: Wiring) -> Dict[Tuple, SiblingCandidate]:
    conf = wiring.conf
    prepared_targets = preparation.run(conf, wiring.target_provider)
    _perform_harvesting(prepared_targets, wiring)
    candidates = _prepare_evaluation(prepared_targets, conf)
    prepared_targets.clear()
    gc.collect()
    return candidates
