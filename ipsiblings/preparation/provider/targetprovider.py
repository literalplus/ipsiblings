import abc
from typing import Dict

from ... import config
from ...model import Target


class TargetProvider(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def configure(self, conf: config.AppConfig):
        """Prepare the provider, fetching any necessary data via the configuration"""
        raise NotImplementedError

    @abc.abstractmethod
    def provide(self) -> Dict[str, Target]:
        """Provide targets for preparation"""
        raise NotImplementedError
