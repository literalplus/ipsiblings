from ipsiblings import liblog
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingStatus
from ipsiblings.evaluation.evaluator.tcpraw import TcprawEvaluator

log = liblog.get_root_logger()

_EVALUATORS = [
    TcprawEvaluator(TcprawEvaluator.SCHEITLE_DIFF_THRESHOLD, 'Scheitle et al.'),
    TcprawEvaluator(TcprawEvaluator.STARKE_DIFF_THRESHOLD, 'Starke')
]


def evaluate_with_all(evaluated_sibling: EvaluatedSibling):
    # TODO: low runtime ?
    for evaluator in _EVALUATORS:
        try:
            result = evaluator.evaluate(evaluated_sibling)
            evaluated_sibling.classifications[evaluator.key] = result
        except Exception:
            evaluated_sibling.classifications[evaluator.key] = SiblingStatus.ERROR
            log.exception(f'Failed to evaluate {evaluated_sibling} with {evaluator.key}')
