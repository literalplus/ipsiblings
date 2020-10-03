import pathlib
from typing import List

from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.model import const


class DomainEvaluator(SiblingEvaluator):
    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        return cls()

    def __init__(self):
        super().__init__(const.EvaluatorChoice.DOMAIN)

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        # this is a set, we have to IP families, so if we only have one domain, they both have the same
        # Note that this depends on every node having a domain assigned, which is the case for the Bitcoin
        # target provider
        if len(evaluated_sibling.domains) == 1:
            return SiblingStatus.POSITIVE
        else:
            return SiblingStatus.INDECISIVE
