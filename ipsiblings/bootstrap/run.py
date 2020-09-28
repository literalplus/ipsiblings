import gc

from .candidate_provider import CandidateProvider
from .wiring import Wiring
from .. import liblog, preparation, config, harvesting
from ..evaluation import EvaluationProcessor
from ..model import PreparedTargets, JustExit, DataException
from ..preparation.serialization import TargetSerialization

"""
Runs the actual business logic of the application, calling high-level API methods of other modules.
"""

log = liblog.get_root_logger()


def run(wiring: Wiring):
    log.info('Application is running.')
    prepared_targets = preparation.run(wiring.conf, wiring.target_provider)
    _do_harvesting(prepared_targets, wiring)
    gc.collect()
    _check_evaluation(prepared_targets, wiring.conf)
    _run_evaluation_batched(prepared_targets, wiring)


def _do_harvesting(prepared_targets: PreparedTargets, wiring: Wiring):
    TargetSerialization.export_targets(prepared_targets, wiring.conf.base_dir, wiring.conf.flags.always_harvest)
    did_run = False
    try:
        did_run = harvesting.run(prepared_targets, wiring.conf, wiring.nic)
    finally:
        if did_run:
            log.info('Exporting targets after harvesting.')
            TargetSerialization.export_targets(prepared_targets, wiring.conf.base_dir, wiring.conf.flags.always_harvest)


def _check_evaluation(prepared_targets: PreparedTargets, conf: config.AppConfig):
    if conf.eval.skip:
        log.warning('No evaluation requested. Exiting.')
        raise JustExit
    if not prepared_targets.has_timestamps():
        raise DataException('No timestamps available, was only a port scan requested?')


def _run_evaluation_batched(prepared_targets, wiring):
    batches = CandidateProvider(prepared_targets, wiring.conf) \
        .as_batches(wiring.conf.eval.batch_size)
    evaluator = EvaluationProcessor(wiring.conf)
    i = 0
    for batch_iter in batches:
        # noinspection PyBroadException
        try:
            log.debug(f'Evaluating batch #{i}...')
            evaluator.run(i, batch_iter)
        except Exception:
            log.exception(f'Failed to evaluate batch #{i}')
            if wiring.conf.eval.fail_fast:
                raise
        finally:
            i += 1
