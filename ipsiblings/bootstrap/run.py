import gc
from typing import Dict

from ipsiblings import liblog, preparation, bootstrap, config, libsiblings
from ipsiblings.bootstrap import Wiring
from ipsiblings.bootstrap.exception import JustExit, DataException
from ipsiblings.libsiblings import SiblingCandidate
from ipsiblings.libts.harvester import provide_harvester_for
from ipsiblings.preparation import PreparedTargets

log = liblog.get_root_logger()


def perform_harvesting(prepared_targets: PreparedTargets, wiring: bootstrap.Wiring):
    conf = wiring.conf
    if conf.flags.do_harvest:
        if not prepared_targets.has_timestamps():  # only harvest if not already done
            log.info('Starting harvesting task ...')
            harvester = provide_harvester_for(wiring, prepared_targets)
            try:
                harvester.start()
                while not harvester.finished():
                    harvester.process_results_running()
                harvester.process_results_final()
            finally:
                log.info('Total records processed: {0}'.format(harvester.total_records_processed()))
                log.info('Now writing harvesting data ...')
                prepared_targets.notify_timestamps_added(conf.base_dir)
                log.info('Finished writing timestamp data')

        else:
            log.warning(f'Not harvesting, it was already done - {prepared_targets.get_kind()}')


def prepare_evaluation(prepared_targets: PreparedTargets, conf: config.AppConfig) -> Dict[str, SiblingCandidate]:
    if conf.skip_evaluation:
        log.warning('No evaluation requested (--no-evaluation). Exiting.')
        raise JustExit
    # stop here if only portscan was requested
    if not prepared_targets.has_timestamps():
        raise DataException('No timestamps available, was only a port scan requested?')
    candidates = libsiblings.construct_candidates_for(prepared_targets, conf)
    if not candidates:
        raise DataException('No sibling candidates available')
    log.info(f'Constructed {len(candidates)} sibling candidates')
    return candidates


def run(wiring: Wiring) -> Dict[str, SiblingCandidate]:
    conf = wiring.conf
    prepared_targets = preparation.run(wiring)
    perform_harvesting(prepared_targets, wiring)
    candidates = prepare_evaluation(prepared_targets, conf)
    prepared_targets.clear()
    gc.collect()
    return candidates
