import gc

from ._nic import obtain_nic
from .. import logsetup, libconstants, preparation
from ..config.model import AppConfig
from ..ostuning import OsTuning


class Wiring:
    """
    Holds and initialises major singleton objects used around the application, inspired by  Dependency Injection,
    but implemented as a poor person's solution with a single object holding everything.
    """

    def __init__(self, conf: AppConfig):
        self.conf: AppConfig = conf
        self.nic = obtain_nic(conf.targetprovider.skip_ip_versions)
        self.log = logsetup.get_root_logger()
        self.target_provider = preparation.get_provider(conf.targetprovider.provider)
        self.target_provider.configure(conf)
        self.os_tuning = OsTuning(conf.os_tuner)


def bridge_wiring_to_legacy(wiring: Wiring, const: libconstants):
    """
    Bridges objects from wiring into the legacy constant module for compatibility with existing code.
    """
    if not gc.isenabled():
        gc.enable()
