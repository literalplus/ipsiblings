import pathlib
from typing import List, Dict, Type

from ipsiblings import liblog
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.bitcoin_protocol import BitcoinEvaluator, BitcoinProperty
from ipsiblings.evaluation.evaluator.domain import DomainEvaluator
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.evaluator.ml import MachineLearningEvaluator
from ipsiblings.evaluation.evaluator.ssh_keyscan import SshKeyscanEvaluator
from ipsiblings.evaluation.evaluator.tcp_options import TcpOptionsEvaluator
from ipsiblings.evaluation.evaluator.tcpraw import ScheitleTcprawEvaluator, StarkeTcprawEvaluator
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.model import const

log = liblog.get_root_logger()

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


def _evaluate_one(evaluated_sibling: EvaluatedSibling, evaluators: List[SiblingEvaluator], fail_fast: bool) -> bool:
    if evaluated_sibling.has_property(BitcoinProperty):
        prop = evaluated_sibling.get_property(BitcoinProperty)
        if prop.all_signs_point_to_no():
            return False
    for evaluator in evaluators:
        # noinspection PyBroadException
        try:
            result = evaluator.evaluate(evaluated_sibling)
            evaluated_sibling.classifications[evaluator.key] = result
        except Exception:
            evaluated_sibling.classifications[evaluator.key] = SiblingStatus.ERROR
            log.exception(f'Failed to evaluate {evaluated_sibling} with {evaluator.key}')
            if fail_fast:
                raise
    return True


def evaluate_with_all(evaluated_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
    # TODO: low runtime ?
    evaluators = _provide_all(evaluated_siblings, batch_dir, conf)
    skipped = 0
    for evaluated_sibling in evaluated_siblings:
        if not _evaluate_one(evaluated_sibling, evaluators, conf.eval.fail_fast):
            skipped += 1
    log.debug(f'Skipped {skipped} targets due to BTC check.')
