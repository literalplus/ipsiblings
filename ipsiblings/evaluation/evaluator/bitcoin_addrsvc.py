import pathlib
from typing import List

from ipsiblings import logsetup
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.evaluation.property.bitcoin_addr_neighbors import BitcoinAddrNeighborsProperty, SharedAddr
from ipsiblings.model import const

log = logsetup.get_root_logger()


class AddrSvcEvaluator(SiblingEvaluator):
    """
    Evaluates based on invariants of Bitcoin ADDR packets - service flags.
    In particular, this uses the implementation detail that service flags are never removed in Bitcoin core.
    """

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        instance = cls()
        return instance

    def __init__(self):
        super().__init__(const.EvaluatorChoice.BITCOIN_ADDR_SVC)

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        prop = evaluated_sibling.contribute_property_type(BitcoinAddrNeighborsProperty)
        if not prop:
            return SiblingStatus.ERROR
        for neighbor in prop.neighbors:
            if self._any_addr_lost_svc_flag(neighbor.shared_addrs_prev) or \
                    self._any_addr_lost_svc_flag(neighbor.shared_addrs_next):
                return SiblingStatus.NEGATIVE
        # no contradiction
        return SiblingStatus.INDECISIVE

    def _any_addr_lost_svc_flag(self, shared_addrs: List[SharedAddr]) -> bool:
        # tuple structure: time, svc, ip, port
        for shared_addr in shared_addrs:
            later_svc = shared_addr.later_info[1]
            earlier_svc = shared_addr.earlier_info[1]
            bits_in_any = later_svc | earlier_svc
            if bits_in_any != later_svc:
                # earlier includes a bit that is no in later
                return True
        return False
