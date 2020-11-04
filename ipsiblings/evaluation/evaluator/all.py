import pathlib
from typing import List, Dict, Type

from ipsiblings import logsetup
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.bitcoin_protocol import BitcoinEvaluator
from ipsiblings.evaluation.evaluator.domain import DomainEvaluator
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.evaluator.ml import MachineLearningEvaluator
from ipsiblings.evaluation.evaluator.ssh_keyscan import SshKeyscanEvaluator
from ipsiblings.evaluation.evaluator.tcp_options import TcpOptionsEvaluator
from ipsiblings.evaluation.evaluator.tcpraw import ScheitleTcprawEvaluator, StarkeTcprawEvaluator
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.evaluation.stats.model import Stats
from ipsiblings.model import const

log = logsetup.get_root_logger()

_PROVIDERS: Dict[const.EvaluatorChoice, Type[SiblingEvaluator]] = {
    const.EvaluatorChoice.TCPRAW_SCHEITLE: ScheitleTcprawEvaluator,
    const.EvaluatorChoice.TCPRAW_STARKE: StarkeTcprawEvaluator,
    const.EvaluatorChoice.DOMAIN: DomainEvaluator,
    const.EvaluatorChoice.SSH_KEYSCAN: SshKeyscanEvaluator,
    const.EvaluatorChoice.TCP_OPTIONS: TcpOptionsEvaluator,
    const.EvaluatorChoice.ML_STARKE: MachineLearningEvaluator,
    const.EvaluatorChoice.BITCOIN: BitcoinEvaluator,
}


def _provide_all(
        evaluated_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig
) -> List[SiblingEvaluator]:
    evaluators = []
    for key, provider in _PROVIDERS.items():
        if key not in conf.eval.evaluators:
            continue
        # noinspection PyBroadException
        try:
            evaluators.append(provider.provide(evaluated_siblings, batch_dir, conf))
        except Exception:
            log.exception(f'Failed to init evaluator for {key}, skipping.')
    return evaluators


def _evaluate_one(evaluated_sibling: EvaluatedSibling, evaluators: List[SiblingEvaluator], fail_fast: bool):
    for evaluator in evaluators:
        # noinspection PyBroadException
        try:
            result = evaluator.evaluate(evaluated_sibling)
            if result is None:
                result = SiblingStatus.INDECISIVE
            evaluated_sibling.classifications[evaluator.key] = result
        except Exception:
            evaluated_sibling.classifications[evaluator.key] = SiblingStatus.ERROR
            log.exception(f'Failed to evaluate {evaluated_sibling} with {evaluator.key}')
            if fail_fast:
                raise


def evaluate_with_all(
        evaluated_siblings: List[EvaluatedSibling], stats: Stats,
        batch_dir: pathlib.Path, conf: AppConfig
):
    # TODO: low runtime ?
    evaluators = _provide_all(evaluated_siblings, batch_dir, conf)
    log.debug(f'Evaluators: {[it.key.name for it in evaluators]}')
    for evaluated_sibling in evaluated_siblings:
        _evaluate_one(evaluated_sibling, evaluators, conf.eval.fail_fast)
        stats.add_result(
            evaluated_sibling[4].target_ip, evaluated_sibling[6].target_ip,
            evaluated_sibling.overall_status, evaluated_sibling.classifications
        )
