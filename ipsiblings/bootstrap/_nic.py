# network.py
#
# (c) 2018 Marco Starke
#

import ipaddress
from typing import List

import netifaces

from ipsiblings import logsetup
from ipsiblings.model.exception import ConfigurationException
from ipsiblings.model.nicinfo import NicInfo

log = logsetup.get_root_logger()


def obtain_nic(skip_ip_versions: List[int]) -> NicInfo:
    nic_list = _get_dualstack_nic_names(skip_ip_versions)
    if not nic_list:
        raise ConfigurationException('Unable to find any Dual-Stack NIC')
    else:
        nic_name = nic_list[0]
    mac = _get_nic_mac(iface=nic_name)
    ip4, ip6 = _get_nic_addresses(iface=nic_name)
    info = NicInfo(nic_name, mac, ip4, ip6)
    log.info(f'Found Dual Stack interfaces: {nic_list}, using {info}')
    return info


def _get_dualstack_nic_names(skip_ip_versions: List[int]):
    """
    Check if Dual Stack is available and return a sorted list of interfaces.
    """
    dual_stack_nics = []
    nic_names = netifaces.interfaces()
    for nic_name in nic_names:
        v4_eligible = 4 in skip_ip_versions or _has_nic_global_ipv4(nic_name)
        v6_eligible = 6 in skip_ip_versions or _has_nic_global_ipv6(nic_name)
        if v4_eligible and v6_eligible:
            dual_stack_nics.append(nic_name)
    dual_stack_nics.sort()
    return dual_stack_nics


def _has_nic_global_ipv4(nic_name: str) -> bool:
    if netifaces.AF_INET not in netifaces.ifaddresses(nic_name):
        return False
    for addresses in netifaces.ifaddresses(nic_name)[netifaces.AF_INET]:
        try:
            if ipaddress.ip_address(addresses['addr']).is_global:
                return True
        except (KeyError, ValueError):
            continue  # ignore parsing errors
    return False


def _has_nic_global_ipv6(nic_name: str) -> bool:
    if netifaces.AF_INET6 not in netifaces.ifaddresses(nic_name):
        return False
    for addresses in netifaces.ifaddresses(nic_name)[netifaces.AF_INET6]:
        try:
            # scoped addresses (e.g. 'fe80::be76:4eff:fe10:5b8d%eth0') do not work, so split off the scope
            if ipaddress.ip_address(addresses['addr'].split('%')[0]).is_global:
                return True
        except (KeyError, ValueError):
            continue  # ignore parsing errors
    return False


def _get_nic_mac(iface='en0'):
    try:
        return netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
    except Exception as e:
        log.warning('Exception: {0}'.format(str(e)))
        return ''


def _get_nic_addresses(iface='en0'):
    v4addr = None
    v6addr = None

    try:
        ifaddr = netifaces.ifaddresses(iface)

        if netifaces.AF_INET in ifaddr.keys():
            links = ifaddr[netifaces.AF_INET]
            for link in links:
                if 'addr' in link.keys() and 'peer' not in link.keys():  # exclude 'peer' (loopback address)
                    v4addr = link['addr']

        if netifaces.AF_INET6 in ifaddr.keys():
            links = ifaddr[netifaces.AF_INET6]
            for link in links:
                if 'addr' in link.keys() and link['addr'].startswith('2'):  # only global
                    v6addr = link['addr']
    except:
        pass

    return v4addr, v6addr
