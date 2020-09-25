from typing import List

from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingStatus
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator


class DomainEvaluator(SiblingEvaluator):
    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], conf: AppConfig):
        return cls()

    def __init__(self):
        super().__init__(f'FQDN')

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        # this is a set, we have to IP families, so if we only have one domain, they both have the same
        # Note that this depends on every node having a domain assigned, which is the case for the Bitcoin
        # target provider
        if len(evaluated_sibling.domains) == 1:
            return SiblingStatus.POSITIVE
        else:
            return SiblingStatus.INDECISIVE
