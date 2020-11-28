import pathlib
from typing import List, Tuple, Optional

from ipsiblings import logsetup
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.evaluation.property.bitcoin_addr_neighbors import BitcoinAddrNeighborsProperty, SharedAddr
from ipsiblings.harvesting.btc.model import BitcoinConnection
from ipsiblings.model import const

log = logsetup.get_root_logger()


class AddrEvaluator(SiblingEvaluator):
    """
    Evaluates based on invariants of Bitcoin ADDR timestamps.
    """

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        instance = cls()
        return instance

    def __init__(self):
        super().__init__(const.EvaluatorChoice.BITCOIN_ADDR)

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        prop = evaluated_sibling.contribute_property_type(BitcoinAddrNeighborsProperty)
        if not prop:
            return SiblingStatus.ERROR
        for neighbor in prop.neighbors:
            if self._any_diff_too_small(neighbor.shared_addrs_next, neighbor.next_v6) or \
                    self._any_diff_too_small(neighbor.shared_addrs_prev, neighbor.v4):
                return SiblingStatus.NEGATIVE
        return SiblingStatus.INDECISIVE

    def _any_diff_too_small(
            self, shared_addrs: List[SharedAddr], later_conn: Optional[BitcoinConnection]
    ) -> bool:
        if not later_conn:
            return False
        for shared_addr in shared_addrs:
            # whether to update is checked when updating so we only care if the addr was active later
            later_active = self._is_addr_active(shared_addr.later_info, later_conn)
            if later_active:
                min_diff = 60 * 60
            else:
                min_diff = 24 * 60 * 60
            if shared_addr.ts_diff_secs < min_diff:
                return True
        return False

    def _is_addr_active(self, tup: Tuple[int, int, str, int], conn: BitcoinConnection) -> bool:
        # tup: time, svc, ip, port
        # IMPORTANT: This formula is too loose! Bitcoin considers the *actual* address timestamp
        # when checking for active, i.e. the two-hour penalty is only applied *after* this check.
        # Therefore, we'd need to either add two hours to the observed timestamp or increase the
        # threshold to 26 hours. This is left incorrect for consistency with existing analyses.
        ts_age_earlier = conn.ver_info.timestamp - tup[0]
        return ts_age_earlier < 24 * 60 * 60
