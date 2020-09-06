import abc
from typing import List, Dict

from .. import config
from ..libts.candidatepair import CandidatePair


class TargetProvider(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def configure(self, conf: config.AppConfig) -> None:
        """Prepare the provider, fetching any necessary data via the configuration"""
        raise NotImplementedError

    @abc.abstractmethod
    def provide_targets(self) -> List[(List[str], str, str)]:
        """Provide targets as a list of (domains, ip4, ip6)"""
        raise NotImplementedError

    @abc.abstractmethod
    def provide_candidates(self) -> Dict[(str, str), CandidatePair]:
        """Provide targets as a mapping (ip4, ip6) -> CandidatePair"""
        raise NotImplementedError
