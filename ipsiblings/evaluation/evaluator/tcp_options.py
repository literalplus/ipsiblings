import pathlib
from typing import List

from ipsiblings import liblog
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingStatus
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.model import const

log = liblog.get_root_logger()


class TcpOptionsEvaluator(SiblingEvaluator):
    """
    Evaluates based on TCP options signatures.
    """

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        instance = cls()
        return instance

    def __init__(self):
        super().__init__(const.EvaluatorChoice.SSH_KEYSCAN)

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        if any([not opts or not len(opts) for opts in evaluated_sibling.tcp_options.items()]):
            return SiblingStatus.ERROR
        opts4, opts6 = evaluated_sibling.tcp_options[4], evaluated_sibling.tcp_options[6]
        iter4, iter6 = iter(opts4), iter(opts6)
        while True:  # Cannot use walrus operator due to Python 3.7 support
            opt4, opt6 = next(iter4, None), next(iter6, None)
            if not opt4 and not opt6:
                # Checked all options, length equal, not empty due to check above
                return SiblingStatus.POSITIVE
            if not opt4 or not opt6:
                # Different length
                return SiblingStatus.NEGATIVE
            (name4, value4), (name6, value6) = opt4, opt6
            if name4 != name6:
                return SiblingStatus.NEGATIVE
            if name4 == 'WScale' and value4 != value6:
                # Scheitle et al. p. 3, right center
                return SiblingStatus.NEGATIVE
