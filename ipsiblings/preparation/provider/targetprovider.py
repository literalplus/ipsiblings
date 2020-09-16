import abc

from ... import config
from ...model import PreparedTargets


class TargetProvider(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def configure(self, conf: config.AppConfig):
        """Prepare the provider, fetching any necessary data via the configuration"""
        raise NotImplementedError

    @abc.abstractmethod
    def provide(self) -> PreparedTargets:
        """Provide targets for preparation"""
        raise NotImplementedError
