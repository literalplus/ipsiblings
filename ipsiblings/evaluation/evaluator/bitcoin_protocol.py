import pathlib
from typing import List, Dict, Optional, Any, Set, Tuple

from ipsiblings import liblog
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.model import FamilySpecificSiblingProperty
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.harvesting.btc.export import BtcImporter
from ipsiblings.harvesting.btc.model import BitcoinConnection
from ipsiblings.model import const

log = liblog.get_root_logger()


class BitcoinConnections:
    def __init__(self, first_conn: BitcoinConnection):
        self.connections: List[BitcoinConnection] = [first_conn]
        self.proto_ver: Optional[int] = first_conn.ver_info.proto_ver
        self.sub_ver: Optional[str] = first_conn.ver_info.sub_ver
        self.services: Optional[int] = first_conn.ver_info.services
        # TODO: check R^2 of block height

    def accept(self, conn: BitcoinConnection):
        if conn.ver_info.proto_ver != self.proto_ver:
            self.proto_ver = None
        if conn.ver_info.sub_ver != self.sub_ver:
            self.sub_ver = None
        if conn.ver_info.services != self.services:
            self.services = None

    def is_consistent(self):
        return self.proto_ver is not None and self.sub_ver is not None and self.services is not None


class BitcoinProperty(FamilySpecificSiblingProperty[Optional[BitcoinConnections]]):
    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return {'proto_ver4', 'sub_ver4', 'proto_ver6', 'sub_ver6'}

    @classmethod
    def provide_for(cls, evaluated_sibling: 'EvaluatedSibling') -> 'BitcoinProperty':
        return cls()

    def __init__(self):
        self.data4: Optional[BitcoinConnections] = None
        self.data6: Optional[BitcoinConnections] = None

    def __setitem__(self, key, value):
        if key == 4:
            self.data4 = value
        elif key == 6:
            self.data6 = value
        else:
            raise KeyError

    def has_response_for_both(self):
        return self[4] and self[6]

    def can_conclude(self):
        return self.has_response_for_both() and self.data4.is_consistent() and self.data6.is_consistent()

    def all_signs_point_to_no(self):
        return self.can_conclude() and (
                self[4].proto_ver != self[6].proto_ver or
                self[4].sub_ver != self[6].sub_ver or
                self[4].services != self[6].services
        )

    def accept(self, conn: BitcoinConnection):
        conns = self[conn.ip_ver]
        if not conns:
            self[conn.ip_ver] = BitcoinConnections(conn)
        else:
            conns.accept(conn)

    def export(self) -> Dict[str, Any]:
        return {
            'proto_ver4': self[4].proto_ver if self[4] else '',
            'proto_ver6': self[6].proto_ver if self[6] else '',
            'sub_ver4': self[4].sub_ver if self[4] else '',
            'sub_ver6': self[6].sub_ver if self[6] else '',
        }


class BitcoinEvaluator(SiblingEvaluator):
    """
    Evaluates based on the results of Bitcoin protocol harvesting.
    """

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        # Do not use base_dir from param since we want to share keyscan results between batches
        instance = cls(pathlib.Path(conf.base_dir))
        instance.init_data_for(all_siblings)
        return instance

    def __init__(self, base_dir: pathlib.Path):
        super().__init__(const.EvaluatorChoice.BITCOIN)
        self.importer = BtcImporter(base_dir)
        self.__init_done = False

    def init_data_for(self, all_siblings: List[EvaluatedSibling]):
        relevant_ips = {(ser.ip_version, ser.target_ip) for sibling_series in all_siblings for ser in sibling_series}
        results = self.importer.read_relevant(relevant_ips)
        log.debug(f'Read {len(results)} relevant Bitcoin results from filesystem.')
        self._apply_results_to(results, all_siblings)
        self.__init_done = True

    def _apply_results_to(
            self, results: Dict[Tuple[int, str], List[BitcoinConnection]], targets: List[EvaluatedSibling]
    ):
        for scan_target in targets:
            prop = scan_target.contribute_property_type(BitcoinProperty)
            for series in scan_target:
                conns = results.get((series.ip_version, series.target_ip))
                if not conns:
                    continue
                for conn in conns:
                    prop.accept(conn)

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        if not self.__init_done:
            raise AssertionError('You probably meant to call init_data_for() first')
        if not evaluated_sibling.has_property(BitcoinProperty):
            return SiblingStatus.ERROR
        prop = evaluated_sibling.get_property(BitcoinProperty)
        if not prop.can_conclude():
            return SiblingStatus.ERROR
        if prop.all_signs_point_to_no():
            return SiblingStatus.NEGATIVE
        else:
            return SiblingStatus.INDECISIVE
