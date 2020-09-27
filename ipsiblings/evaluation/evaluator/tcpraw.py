import abc
from typing import List

from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingStatus
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.property.raw_tcp_ts_diff import FirstTimestampDiffProperty


class TcprawEvaluator(SiblingEvaluator, metaclass=abc.ABCMeta):

    def __init__(self, threshold: float, name: str):
        super().__init__(f'Δtcp_raw ({name})')
        self.threshold_tcpraw = threshold

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        # This throws if calculation should fail, so we do not need to handle this case by e.g. if delta_tcpraw
        diff_prop = evaluated_sibling.contribute_property_type(FirstTimestampDiffProperty)
        delta_tcpraw = diff_prop.raw_timestamp_diff
        if delta_tcpraw <= self.threshold_tcpraw:
            return SiblingStatus.POSITIVE
        else:
            return SiblingStatus.NEGATIVE


class ScheitleTcprawEvaluator(TcprawEvaluator):
    THRESHOLD = 0.2557  # Scheitle at al. 2017

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], conf: AppConfig):
        return cls(cls.THRESHOLD, 'Scheitle et al.')


class StarkeTcprawEvaluator(TcprawEvaluator):
    THRESHOLD = 0.305211037  # Starke 2019

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], conf: AppConfig):
        return cls(cls.THRESHOLD, 'Starke')
