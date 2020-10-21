# libsiblings/construct_candidates.py
#
# (c) 2018 Marco Starke
#
# The code in this file is loosely based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#
from itertools import islice
from typing import Iterator, Optional

from ipsiblings import liblog
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.target_btc_versions import TargetBtcVersions
from ipsiblings.model import SiblingCandidate, PreparedTargets

log = liblog.get_root_logger()


class CandidateProvider:
    def __init__(self, prepared_targets: PreparedTargets, conf: AppConfig):
        log.debug('Splitting targets by IP version, skipping non-responsive ones.')
        self.targets4 = [t for t in prepared_targets if t.ip_version == 4 and t.has_any_timestamp()]
        self.targets6 = [t for t in prepared_targets if t.ip_version == 6 and t.has_any_timestamp()]
        log.debug(f'Retained {len(self.targets4)} IPv4 / {len(self.targets6)} IPv6 targets. Loading BTC data...')
        prepared_targets.clear()
        self.versions = TargetBtcVersions(conf.base_dir)
        log.debug(f'Loaded harvested Bitcoin versions for {len(self.versions.target_versions_map)} addresses.')
        self.skip_count = 0

    def __iter__(self) -> Iterator[Optional[SiblingCandidate]]:
        for target4 in self.targets4:
            for target6 in self.targets6:
                if self.versions.is_match_possible(target4, target6):
                    yield SiblingCandidate(target4, target6)
                else:
                    yield None  # otherwise batching is not reliably possible w/o doing btc check on skipped batches

    def as_batches(self, batch_size: int) -> Iterator[Iterator[SiblingCandidate]]:
        iterator = iter(self)
        while True:  # gotta love Debian only shipping Python 3.7, so cannot use Walrus operator :(
            batch = islice(iterator, batch_size)
            if not batch:
                return
            yield filter(lambda x: x is not None, batch)
