import gc

from .candidate_provider import CandidateProvider
from .wiring import Wiring
from .. import logsetup, preparation, config, harvesting
from ..evaluation import EvaluationProcessor
from ..model import PreparedTargets, JustExit, DataException
from ..preparation.serialization import TargetSerialization

"""
Runs the actual business logic of the application, calling high-level API methods of other modules.
"""

log = logsetup.get_root_logger()


def run(wiring: Wiring):
    log.info('Application is running.')
    prepared_targets = preparation.run(wiring.conf, wiring.target_provider)
    _do_harvesting(prepared_targets, wiring)
    gc.collect()
    _check_evaluation(prepared_targets, wiring.conf)
    _run_evaluation_batched(prepared_targets, wiring)


def _do_harvesting(prepared_targets: PreparedTargets, wiring: Wiring):
    if TargetSerialization.target_file_exists(wiring.conf.base_dir) and not wiring.conf.flags.do_harvest:
        log.info('Not harvesting or exporting targets.')
        return
    TargetSerialization.export_targets(prepared_targets, wiring.conf.base_dir, wiring.conf.flags.always_harvest)
    did_run = True  # we want to save in exceptional cases (i.e. where this variable does not get overwritten)
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
    candidate_provider = CandidateProvider(prepared_targets, wiring.conf)
    evaluator = EvaluationProcessor(wiring.conf)
    i = 0
    batches_processed = 0
    for batch_iter in candidate_provider.as_batches(wiring.conf.eval.batch_size):
        if i < wiring.conf.eval.first_batch_idx:
            i += 1
            continue
        # noinspection PyBroadException
        try:
            batches_processed += 1
            log.debug(f'Evaluating batch #{i}...')
            evaluator.run(i, batch_iter)
        except Exception:
            log.exception(f'Failed to evaluate batch #{i}')
            if wiring.conf.eval.fail_fast:
                raise
        finally:
            i += 1
        if 0 <= wiring.conf.eval.batch_count <= batches_processed:
            log.info(f'Stopping evaluation after {batches_processed} batches as requested.')
            break
    log.info(f'Skipped {candidate_provider.skip_count} candidate pairs due to Bitcoin version mismatch')
