import gc
from typing import Dict, Tuple

from . import construct_candidates
from .wiring import Wiring
from .. import liblog, preparation, config, evaluation, harvesting
from ..model import SiblingCandidate, PreparedTargets, JustExit, DataException
from ..preparation.serialization import TargetSerialization

"""
Runs the actual business logic of the application, calling high-level API methods of other modules.
"""

log = liblog.get_root_logger()


def _do_harvesting(prepared_targets: PreparedTargets, wiring: Wiring):
    TargetSerialization.export_targets(prepared_targets, wiring.conf.base_dir)
    try:
        harvesting.run(prepared_targets, wiring.conf, wiring.nic)
    finally:
        log.info('Exporting targets after harvesting.')
        TargetSerialization.export_targets(prepared_targets, wiring.conf.base_dir)


def _prepare_evaluation(prepared_targets: PreparedTargets, conf: config.AppConfig) -> Dict[Tuple, SiblingCandidate]:
    if conf.eval.skip:
        log.warning('No evaluation requested. Exiting.')
        raise JustExit
    if not prepared_targets.has_timestamps():
        raise DataException('No timestamps available, was only a port scan requested?')
    candidates = construct_candidates.construct_candidates_for(prepared_targets, conf)
    if not candidates:
        raise DataException('No sibling candidates available - do we have targets for both address families?')
    log.info(f'Constructed {len(candidates)} sibling candidates')
    return candidates


def run(wiring: Wiring):
    log.info('Application is running.')
    prepared_targets = preparation.run(wiring.conf, wiring.target_provider)
    _do_harvesting(prepared_targets, wiring)
    candidates = _prepare_evaluation(prepared_targets, wiring.conf)
    prepared_targets.clear()
    gc.collect()
    evaluation.run(candidates, wiring.conf)
