# network.py
#
# (c) 2018 Marco Starke
#

import ipaddress
import socket

import netifaces

from .misc import is_iterable
from .. import libconstants as const
from .. import liblog
from ..model import ConfigurationException

log = liblog.get_root_logger()


class NicInfo:
    def __init__(self, name):
        self.name = name
        self.mac: str = get_mac(iface=name).lower()
        own_ip4, own_ip6 = _getiface_ips(iface=name)
        self.ip4: str = own_ip4
        self.ip6: str = own_ip6.lower()

    def __str__(self):
        return f'NicInfo({self.name}: mac={self.mac}, ip4={self.ip4}, ip6={self.ip6})'


def obtain_nic() -> NicInfo:
    nic_list = _get_dualstack_nic_names()
    if not nic_list:
        raise ConfigurationException('Unable to find any Dual-Stack NIC')
    else:
        nicname = nic_list[0]
    info = NicInfo(nicname)
    log.info(f'Found Dual Stack interfaces: {nic_list}, using {info}')
    return info


def _get_dualstack_nic_names():
    """
    Check if Dual Stack is available and return a sorted list of interfaces.
    """

    dual_stack_nics = []

    ifaces = netifaces.interfaces()

    for nic in ifaces:
        has_ipv4 = False
        has_ipv6 = False

        if netifaces.AF_INET in netifaces.ifaddresses(nic):
            for addresses in netifaces.ifaddresses(nic)[netifaces.AF_INET]:
                try:  # prevent errors while parsing IPv4 address
                    if ipaddress.ip_address(addresses['addr']).is_global:
                        has_ipv4 = True
                        break  # we have a valid global IPv4 address -> break
                except:
                    continue
        else:  # interface does not have an IPv4 address
            continue

        if netifaces.AF_INET6 in netifaces.ifaddresses(nic):
            for addresses in netifaces.ifaddresses(nic)[netifaces.AF_INET6]:
                try:  # scoped addresses (e.g. 'fe80::be76:4eff:fe10:5b8d%eth0') do not work of course
                    if ipaddress.ip_address(addresses['addr'].split('%')[0]).is_global:  # so split off the scope
                        has_ipv6 = True
                        break  # we have a valid global IPv6 address -> break
                except:
                    continue
        else:  # interface does not have an IPv6 address
            continue

        if has_ipv4 and has_ipv6:
            dual_stack_nics.append(nic)

    dual_stack_nics.sort()

    return dual_stack_nics


def get_host_by_ip(ip, verbose=False):
    """
    Returns (name, aliaslist, addresslist) or None on error.
    """
    try:
        return socket.gethostbyaddr(ip)
    except (socket.error, socket.herror, socket.gaierror, socket.timeout) as e:
        if verbose:
            log.debug('Hostname error for [{0}]: '.format(ip) + str(e))
        return None


def get_mac(iface='en0'):
    try:
        return netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
    except Exception as e:
        log.warning('Exception: {0}'.format(str(e)))
        return ''


def _getiface_ips(iface='en0'):
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


def get_ip_from_str(hoststr, ipversion=const.IP_VERSION_4):
    """
    Returns ipaddress.IPv{4,6}Address or None if error occurred.
    If hoststr is either a valid IPv4 or IPv6, ipversion parameter is ignored!
    """
    address = parse_ip(hoststr)
    if address:
        return address
    else:
        address = resolve_host(hoststr, ipversion)
        if address:
            return address

    log.debug('Error extracting IPv{0} from {1}!'.format(ipversion, hoststr))
    return None


def crosscheck_ip_version(address, ipversion):
    if type(address) is ipaddress.IPv4Address and ipversion is const.IP_VERSION_4:
        return True
    elif type(address) is ipaddress.IPv6Address and ipversion is const.IP_VERSION_6:
        return True
    else:
        return False


def is_global(ip, ipversion=None):
    """
    True/False for is IP global.
    None if IP not parseable.
    """
    if ipversion == 4:
        if is_iterable(ip):
            ret = []
            for ipaddr in ip:
                try:
                    addr = ipaddress.ip_address(ipaddr)
                except:
                    ret.append(None)
                ret.append(addr.is_global)
            return ret
        else:
            try:
                addr = ipaddress.ip_address(ip)
            except:
                return None
            return addr.is_global

    elif ipversion == 6:
        if is_iterable(ip):
            ret = []
            for ipaddr in ip:
                try:
                    addr = ipaddress.ip_address(ipaddr)
                except:
                    ret.append(None)
                # workaround for faulty DNS records (2000::/3 -> 3000::/3 valid (0011))
                # e.g. ::7.184.66.129 [or any other IPv4 mapped addresses ::ffff:0:0/96]
                ret.append(addr.is_global and (ipaddr.startswith('2') or ipaddr.startswith('3')))
            return ret
        else:
            # TODO: how is this supposed to work ? did this ever work ?
            try:
                addr.ipaddress.ip_address(ip)
            except:
                return None
            return addr.is_global and (ip.startswith('2') or ip.startswith('3'))

    else:  # determine ip version
        if is_iterable(ip):
            ret = []
            for ipaddr in ip:
                try:
                    addr = ipaddress.ip_address(ipaddr)
                except:
                    ret.append(None)

                if addr.version == 4:
                    ret.append(addr.is_global)
                else:
                    ret.append(addr.is_global and (ipaddr.startswith('2') or ipaddr.startswith('3')))
            return ret
        else:
            try:
                addr = ipaddress.ip_address(ip)
            except:
                return None

            if addr.version == 4:
                return addr.is_global
            else:
                return addr.is_global and (ip.startswith('2') or ip.startswith('3'))


def get_global_ip_addresses(traces, as_set=False):
    """
    Returns a tuple (v4, v6) containing global IP addresses extracted from 'traces'.
    """
    v4list = []
    v6list = []

    for ttl, ip in traces[0].items():
        addr = ipaddress.ip_address(ip)
        if addr.is_global:
            v4list.append(ip)

    for hlim, ip in traces[1].items():
        addr = ipaddress.ip_address(ip)
        if addr.is_global:
            v6list.append(ip)

    if as_set:
        return [set(v4list), set(v6list)]
    else:
        return v4list, v6list
