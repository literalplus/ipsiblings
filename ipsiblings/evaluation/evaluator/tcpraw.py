import abc
import pathlib
from typing import List

from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.evaluation.property.raw_tcp_ts_diff import FirstTimestampDiffProperty
from ipsiblings.model import const


class TcprawEvaluator(SiblingEvaluator, metaclass=abc.ABCMeta):
    """
    Evaluates based on the raw TCP timestamp difference using a constant threshold as defined by
    Scheitle et al. and Starke.
    """

    def __init__(self, threshold: float, key: const.EvaluatorChoice):
        super().__init__(key)
        self.threshold_tcpraw = threshold

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        # This throws if calculation should fail, so we do not need to handle this case by e.g. if delta_tcpraw
        diff_prop = evaluated_sibling.contribute_property_type(FirstTimestampDiffProperty)
        if not diff_prop:
            return SiblingStatus.ERROR
        delta_tcpraw = diff_prop.raw_timestamp_diff
        if delta_tcpraw <= self.threshold_tcpraw:
            return SiblingStatus.POSITIVE
        else:  # Could still be randomised
            return SiblingStatus.INDECISIVE


class ScheitleTcprawEvaluator(TcprawEvaluator):
    THRESHOLD = 0.2557  # Scheitle at al. 2017

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        return cls(cls.THRESHOLD, const.EvaluatorChoice.TCPRAW_SCHEITLE)


class StarkeTcprawEvaluator(TcprawEvaluator):
    THRESHOLD = 0.305211037  # Starke 2019

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        return cls(cls.THRESHOLD, const.EvaluatorChoice.TCPRAW_STARKE)
