# algorithms.topdowntraceroute.py
#
# (c) 2019 Marco Starke
#

import random
import ipaddress
from scapy import all as scapy

import libtools
import libconstants as const
from algorithms.base import Algorithm


class TopDownTracerouteAlgorithm(Algorithm):

  def __init__(self):
    """
    This implementation does not use any constructor arguments.
    """
    pass


  def init(self, algorithm_params = {}): # target_ip, timeout = 2, iface = 'en0', sport = 179, dport = 80, filter = None, retry = 0, multi = False, store_unanswered = False):
    """
    target_ip         ip address of target
    timeout           timeout for tracerout responses in seconds [2]
    iface             interface to use ['en0']
    sport             source port [179]
    dport             destination port [80]
    filter            BPF to reduce captured packets [None]
    retry             if positive, how many times to resend unanswered packets [0]
                      if negative, how many times to retry when no more packets are answered
    multi             accept multiple answers to a packet [False]
    store_unanswered  keep unanswered packets to determine which were unanswered [False]
    """
    self.target_ip = algorithm_params.ipaddress
    self.timeout = algorithm_params.timeout
    self.ipversion = algorithm_params.ipversion
    self.iface = algorithm_params.iface
    self.sport = algorithm_params.srcport
    self.dport = algorithm_params.dstport
    self.filter = algorithm_params.filter
    self.retry = algorithm_params.retry
    self.multi_responses = algorithm_params.multi
    self.store_unanswered = algorithm_params.store_unanswered


  def run(self):
    ts = random.getrandbits(32)

    to_send = []
    seqbase = random.randint(1, 2**24) * 100
    # speed > code optimization
    if self.ipversion == const.IP4:
      own_ip = const.IFACE_IP4_ADDRESS
      base_pkt = scapy.Ether()/scapy.IP(src = own_ip, dst = str(self.target_ip))/scapy.TCP(sport = self.sport, dport = self.dport, flags = 'S', options = [('WScale', 0), ('Timestamp', (ts, 0))])

      for ttl in reversed(range(1,31)):
        p = base_pkt.copy()
        p[scapy.IP].ttl = ttl
        p[scapy.TCP].seq = int(seqbase + ttl) # - 1 # used for sorting
        to_send.append(p)

      if not self.filter:
        # https://github.com/secdev/scapy/blob/c5aefe757f045cb91a8d255a7151bd3cfb9c1077/scapy/layers/inet.py#L1624
        self.filter = '(icmp and (icmp[0]=3 or icmp[0]=4 or icmp[0]=5 or icmp[0]=11 or icmp[0]=12)) or (tcp and (tcp[13] & 0x16 > 0x10))'
    else:
      own_ip = const.IFACE_IP6_ADDRESS
      base_pkt = scapy.Ether()/scapy.IPv6(src = own_ip, dst = str(self.target_ip))/scapy.TCP(sport = self.sport, dport = self.dport, flags = 'S', options = [('WScale', 0), ('Timestamp', (ts, 0))])

      for hlim in reversed(range(1,31)):
        p = base_pkt.copy()
        p[scapy.IPv6].hlim = hlim
        p[scapy.TCP].seq = int(seqbase + hlim) # - 1 # used for sorting
        to_send.append(p)

      if not self.filter:
        # https://github.com/secdev/scapy/blob/c5aefe757f045cb91a8d255a7151bd3cfb9c1077/scapy/layers/inet6.py#L3291
        self.filter = 'icmp6 or tcp'

    a, u = scapy.srp(to_send, timeout = self.timeout, verbose = 0, filter = self.filter, retry = self.retry, multi = self.multi_responses, store_unanswered = self.store_unanswered)

    icmp_responses = {}
    for _, r in a.res:
      if scapy.TCPerror in r:
        ttl = int(r[scapy.TCPerror].seq - seqbase)
        icmp_responses[ttl] = r.payload.src

    trace = dict(sorted(icmp_responses.items())) # { ttl: icmp_responses[ttl] for ttl in sorted(icmp_responses.keys()) }

    if const.TRACEROUTE_ADD_SOURCE_IP:
      trace[0] = own_ip

    if not const.TRACEROUTE_WITHOUT_DESTINATION_IP:
      trace[max(trace.keys()) + 1] = str(self.target_ip)

    return (trace, None)
