from .. import libgeo, liblog, libtools, libconstants, targetprovider
from ..config.model import AppConfig
from ..libtools import SkipList


class Wiring:
    def __init__(self, conf: AppConfig):
        self.conf: AppConfig = conf
        self.geo: libgeo.Geo = libgeo.Geo(conf.geoip)
        self.nic = libtools.network.obtain_nic()
        self.log = liblog.get_root_logger()
        self.target_provider = targetprovider.get_provider(conf.targetprovider.provider)
        self.skip_list = SkipList(conf.paths.ip_ignores)


def bridge_wiring_to_legacy(wiring: Wiring, const: libconstants):
    const.GEO = wiring.geo
    const.NIC_MAC_ADDRESS = wiring.nic.mac
    const.IFACE_IP4_ADDRESS = wiring.nic.ip4
    const.IFACE_IP6_ADDRESS = wiring.nic.ip6
