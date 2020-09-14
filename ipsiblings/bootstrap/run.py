import gc
from typing import Dict, Tuple

from ipsiblings import liblog, preparation, bootstrap, config, libsiblings
from ipsiblings.bootstrap import Wiring
from ipsiblings.bootstrap.exception import JustExit, DataException
from ipsiblings.harvesting.harvester import provide_harvester_for
from ipsiblings.libsiblings import SiblingCandidate
from ipsiblings.preparation import PreparedTargets
from ipsiblings.preparation.serialization import TargetSerialization

"""
Runs the actual business logic of the application, calling high-level API methods of other modules.
"""

log = liblog.get_root_logger()


def perform_harvesting(prepared_targets: PreparedTargets, wiring: bootstrap.Wiring):
    conf = wiring.conf
    if conf.flags.do_harvest:
        if prepared_targets.has_timestamps():
            log.warning(f'Not harvesting, it was already done - {prepared_targets.kind}')
            return
        log.info('Starting harvesting task ...')
        harvester = provide_harvester_for(wiring, prepared_targets)
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


def prepare_evaluation(prepared_targets: PreparedTargets, conf: config.AppConfig) -> Dict[Tuple, SiblingCandidate]:
    if conf.skip_evaluation:
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
    prepared_targets = preparation.run(wiring)
    perform_harvesting(prepared_targets, wiring)
    candidates = prepare_evaluation(prepared_targets, conf)
    prepared_targets.clear()
    gc.collect()
    return candidates
