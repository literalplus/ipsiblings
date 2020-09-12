import abc
from typing import Dict, Tuple, Union, TypeVar, Generic

from ipsiblings import liblog
from ipsiblings.bootstrap.exception import DataException
from ipsiblings.libts.candidatepair import CandidatePair
from ipsiblings.libts.serialization import write_candidate_pairs

T = TypeVar('T')
log = liblog.get_root_logger()


class PreparedTargets(Generic[T], metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_models(self):  # TODO: Declare return type, currently keys are different for impls
        raise NotImplementedError

    @abc.abstractmethod
    def get_model(self, key4, key6) -> Union[T, None]:
        raise NotImplementedError

    @abc.abstractmethod
    def get_kind(self) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def get_total_per_family(self) -> Tuple[int, int]:
        raise NotImplementedError

    @abc.abstractmethod
    def has_timestamps(self):
        raise NotImplementedError

    @abc.abstractmethod
    def notify_timestamps_added(self, base_dir):
        raise NotImplementedError

    @abc.abstractmethod
    def clear(self):
        raise NotImplementedError

    def print_summary(self):
        if not self.get_models():
            raise DataException('No nodes found after preparation, nothing to harvest.')
        nr_active_nodes4, nr_active_nodes6 = self.get_total_per_family()
        total_active_nodes = nr_active_nodes4 + nr_active_nodes6
        if total_active_nodes > 0:
            log.info('IPv4 active nodes: {0} / IPv6 active nodes: {1}'.format(nr_active_nodes4, nr_active_nodes6))
            log.info('Total number active nodes: {0}'.format(total_active_nodes))


class PreparedPairs(PreparedTargets[CandidatePair]):
    KIND = 'CandidatePair'

    def __init__(
            self,
            candidate_pairs: Dict[Tuple[str, str], CandidatePair],
            has_ports: bool, write_count: int, has_timestamps: bool
    ):
        self.candidate_pairs = candidate_pairs
        self.has_ports = has_ports
        self.write_count = write_count
        self._has_timestamps = has_timestamps
        self.cleared = False

    def _check_cleared(self):
        if self.cleared:
            raise DataException('Tried to access PreparedTraceSets after already cleared!')

    def get_kind(self) -> str:
        return self.KIND

    def get_models(self) -> Dict[Tuple[str, str], CandidatePair]:
        self._check_cleared()
        return self.candidate_pairs

    def get_model(self, key4, key6) -> Union[CandidatePair, None]:
        self._check_cleared()
        return self.candidate_pairs.get((key4, key6))

    def get_total_per_family(self) -> Tuple[int, int]:
        self._check_cleared()
        if not self.has_ports:
            return self.write_count, self.write_count
        else:  # if ports are available, all loaded candidates should be active
            cand_cnt = len(self.candidate_pairs)
            return cand_cnt, cand_cnt

    def has_timestamps(self):
        self._check_cleared()
        return self._has_timestamps

    def notify_timestamps_added(self, base_dir):
        self._check_cleared()
        nr_candidates_written, nr_data_records_written = write_candidate_pairs(
            self.candidate_pairs,
            base_dir,
            write_candidates=False,
            write_ts_data=True,
            write_tcp_opts_data=False,
            include_domain=True
        )
        self.write_count = nr_candidates_written
        self._has_timestamps = nr_data_records_written > 0

    def clear(self):
        self.candidate_pairs.clear()
        self.cleared = True
