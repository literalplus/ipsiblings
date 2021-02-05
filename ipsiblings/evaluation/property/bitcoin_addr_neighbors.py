from typing import Tuple, Dict, Set, Optional, List

from ipsiblings import logsetup
from ipsiblings.evaluation.evaluator.bitcoin_protocol import BitcoinProperty
from ipsiblings.evaluation.model.property import SiblingProperty
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.harvesting.btc.model import BitcoinConnection

log = logsetup.get_root_logger()


class SharedAddr:
    """
    A single address shared between two connections that stores information collected in both of them.
    """

    # tuple structure: time, svc, ip, port
    def __init__(self, earlier_info: Tuple[int, int, str, int], later_info: Tuple[int, int, str, int]):
        self.earlier_info = earlier_info
        self.later_info = later_info

    @property
    def ts_diff_secs(self) -> int:
        return self.later_info[0] - self.earlier_info[0]


class AddrNeighbors:
    """Closest neighbours of an IPv4 Bitcoin connection."""

    def __init__(self, v4_conn: BitcoinConnection):
        self.v4 = v4_conn
        self.v4_ip_to_addr_info: Dict[str, Tuple[int, int, str, int]] = {tup[2]: tup for tup in v4_conn.addr_infos}
        self.prev_v6: Optional[BitcoinConnection] = None
        self.next_v6: Optional[BitcoinConnection] = None
        self.shared_addrs_prev: List[SharedAddr] = []
        self.shared_addrs_next: List[SharedAddr] = []

    @property
    def avg_share_count(self):
        return (len(self.shared_addrs_prev) + len(self.shared_addrs_next)) / 2

    def set_next_v6(self, next_v6: BitcoinConnection):
        self.next_v6 = next_v6
        for later_addr_info in next_v6.addr_infos:
            ip = later_addr_info[2]
            if ip in self.v4_ip_to_addr_info:
                self.shared_addrs_next.append(
                    SharedAddr(self.v4_ip_to_addr_info[ip], later_addr_info)
                )

    def set_prev_v6(self, prev_v6: BitcoinConnection):
        self.prev_v6 = prev_v6
        for earlier_addr_info in prev_v6.addr_infos:
            ip = earlier_addr_info[2]
            if ip in self.v4_ip_to_addr_info:
                self.shared_addrs_next.append(
                    SharedAddr(earlier_addr_info, self.v4_ip_to_addr_info[ip])
                )

    def clear_temp(self):
        self.v4_ip_to_addr_info = None


class BitcoinAddrNeighborsProperty(SiblingProperty):
    """
    Calculates closest neighbours (relative to the node's reported timestamp) for each Bitcoin connection.
    Depends on BitcoinProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'Optional[BitcoinAddrNeighborsProperty]':
        if not evaluated_sibling.has_property(BitcoinProperty):
            return None
        # Cannot cache because we use both series
        btc_prop = evaluated_sibling.get_property(BitcoinProperty)
        if not btc_prop.has_response_for_both():
            return None
        return cls(
            cls._calc_neighbors(btc_prop)
        )

    @classmethod
    def _calc_neighbors(cls, source: BitcoinProperty) -> List[AddrNeighbors]:
        v6_iter = iter(source[6].connections)
        result = []
        try:
            prev_v6: BitcoinConnection = next(v6_iter)
        except StopIteration:
            return result
        next_v6: Optional[BitcoinConnection] = prev_v6
        for curr_v4 in source[4].connections:
            neighbor = AddrNeighbors(curr_v4)
            v4_ts = curr_v4.ver_info.timestamp
            while next_v6 is not None and next_v6.ver_info.timestamp < v4_ts:
                prev_v6 = next_v6
                next_v6 = next(v6_iter, None)
            if prev_v6.ver_info.timestamp <= v4_ts:
                # check becomes relevant when the first v6 is after the first v4
                neighbor.set_prev_v6(prev_v6)
            if next_v6 is not None and next_v6.ver_info.timestamp > v4_ts:
                neighbor.set_next_v6(next_v6)
            result.append(neighbor)
        return result

    def __init__(self, neighbors: List[AddrNeighbors]):
        self.neighbors = neighbors
        sum_shared = sum([n.avg_share_count for n in neighbors])
        self.avg_shared_addrs = sum_shared / len(neighbors)

    def export(self) -> Dict[str, float]:
        return {
            'avg_shared': self.avg_shared_addrs
        }

    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return {'avg_shared'}
