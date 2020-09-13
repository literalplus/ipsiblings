import abc
from typing import Dict

from ipsiblings.preparation.candidatepair import CandidatePair
from .. import config


class TargetProvider(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def configure(self, conf: config.AppConfig) -> None:
        """Prepare the provider, fetching any necessary data via the configuration"""
        raise NotImplementedError

    @abc.abstractmethod
    def provide_candidates(self) -> Dict[(str, str), CandidatePair]:
        """Provide targets as a mapping (ip4, ip6) -> CandidatePair"""
        raise NotImplementedError
