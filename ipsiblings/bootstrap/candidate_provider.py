# libsiblings/construct_candidates.py
#
# (c) 2018 Marco Starke
#
# The code in this file is loosely based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#
from itertools import islice
from typing import Iterator

from ipsiblings import liblog
from ipsiblings.config import AppConfig
from ipsiblings.model import SiblingCandidate, PreparedTargets, ConfigurationException

log = liblog.get_root_logger()


class CandidateProvider:
    def __init__(self, prepared_targets: PreparedTargets, conf: AppConfig):
        if conf.candidates.low_runtime:
            raise ConfigurationException('Low-RT is not currently supported.')
        log.debug('Splitting targets by IP version, skipping non-responsive ones.')
        self.targets4 = [t for t in prepared_targets if t.ip_version == 4 and t.has_any_timestamp()]
        log.debug(f'Retained {len(self.targets4)} IPv4 targets.')
        self.targets6 = [t for t in prepared_targets if t.ip_version == 6 and t.has_any_timestamp()]
        log.debug(f'Retained {len(self.targets6)} IPv6 targets.')
        prepared_targets.clear()

    def __iter__(self) -> Iterator[SiblingCandidate]:
        for target4 in self.targets4:
            for target6 in self.targets6:
                yield SiblingCandidate(target4, target6)

    def as_batches(self, batch_size: int) -> Iterator[Iterator[SiblingCandidate]]:
        iterator = iter(self)
        while True:  # gotta love Debian only shipping Python 3.7, so cannot use Walrus operator :(
            batch = islice(iterator, batch_size)
            if not batch:
                break
            yield batch
