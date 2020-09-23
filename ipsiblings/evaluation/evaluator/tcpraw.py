from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingStatus
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.property.raw_tcp_ts_diff import FirstTimestampDiffProperty


class TcprawEvaluator(SiblingEvaluator):
    STARKE_DIFF_THRESHOLD = 0.305211037  # Starke 2019
    SCHEITLE_DIFF_THRESHOLD = 0.2557  # Scheitle at al. 2017

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
