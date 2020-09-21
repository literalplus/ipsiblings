# network.py
#
# (c) 2018 Marco Starke
#

import ipaddress
import socket

import netifaces

from .. import libconstants as const
from .. import liblog
from ..model import ConfigurationException, NicInfo

log = liblog.get_root_logger()


def obtain_nic() -> NicInfo:
    nic_list = _get_dualstack_nic_names()
    if not nic_list:
        raise ConfigurationException('Unable to find any Dual-Stack NIC')
    else:
        nic_name = nic_list[0]
    mac = _get_nic_mac(iface=nic_name)
    ip4, ip6 = _get_nic_addresses(iface=nic_name)
    info = NicInfo(nic_name, mac, ip4, ip6)
    log.info(f'Found Dual Stack interfaces: {nic_list}, using {info}')
    return info


def _get_dualstack_nic_names():
    """
    Check if Dual Stack is available and return a sorted list of interfaces.
    """
    dual_stack_nics = []
    nic_names = netifaces.interfaces()
    for nic_name in nic_names:
        if _has_nic_global_ipv4(nic_name) and _has_nic_global_ipv6(nic_name):
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


def resolve_host(hoststr, ipversion=const.IP_VERSION_4):
    """
    Resolves hoststr to first listed (based on DNS) IP address of ipversion.
    """
    if ipversion is const.IP_VERSION_4:
        try:
            address = socket.getaddrinfo(hoststr, None, socket.AF_INET)[0][4][0]
        except socket.gaierror:
            address = None
    elif ipversion is const.IP_VERSION_6:
        try:
            address = socket.getaddrinfo(hoststr, None, socket.AF_INET6)[0][4][0]
        except socket.gaierror:
            address = None
    else:
        raise ValueError('ipversion must be one of libconstants.IP_VERSION_4 or libconstants.IP_VERSION_6!')

    return ipaddress.ip_address(address)


def resolve_host_dual(hoststr):
    """
    Uses the first address returned by 'getaddrinfo'.
    Returns a tuple of (IPv4, IPv6). None if no IPv4 or IPv6 is available.
    """
    try:
        # [(family, type, proto, canonname, sockaddr)] -> [sockaddr] -> (address, port, flow info, scope id)
        addrv6 = socket.getaddrinfo(hoststr, None, socket.AF_INET6)[0][4][0]
    except socket.gaierror:
        return None

    log.debug('Found IPv6 for host \'{0}\': \'{1}\''.format(hoststr, addrv6))

    try:
        # [(family, type, proto, canonname, sockaddr)] -> [sockaddr] -> (address, port)
        addrv4 = socket.getaddrinfo(hoststr, None, socket.AF_INET)[0][4][0]
    except socket.gaierror:
        return None

    log.debug('Found IPv4 for host \'{0}\': \'{1}\''.format(hoststr, addrv4))

    return ipaddress.ip_address(addrv4), ipaddress.ip_address(addrv6)


def parse_ip(target):
    """
    Returns ipaddress.ip_address(target), None otherwise.
    """
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return None

    return address
