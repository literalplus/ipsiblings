# packets.py
#
# (c) 2018 Marco Starke
#

import scapy.all as scapy

from .. import libconstants as const
from .. import liblog

log = liblog.get_root_logger()


def reply_tcp_RA(dst, dport, sport, ipversion=const.IP_VERSION_4):
    p = scapy.Ether()
    if ipversion is const.IP_VERSION_4:
        p = p / scapy.IP(dst=dst)
    elif ipversion is const.IP_VERSION_6:
        p = p / scapy.IPv6(dst=dst)
    else:
        raise ValueError('Illegal IP version detected [{0}]!'.format(str(ipversion)))

    p = p / scapy.TCP(dport=dport, sport=sport, flags='RA')
    return scapy.sendp(p)


def get_ip_version(packet):
    if packet.haslayer(scapy.Ether):
        return packet.payload.version
    else:
        return packet.version


def get_ts(packet):
    """
    Returns the TCP options timestamp tuple (TSval, TSecr) if available or 'None'.
    ASSUMPTION: TCP layer is present!
    """
    try:
        for opt in packet[scapy.TCP].options:
            if opt[0] == 'Timestamp':
                return opt[1]
    except Exception as e:
        log.error('Exception: {0}'.format(str(e)))

    return None
