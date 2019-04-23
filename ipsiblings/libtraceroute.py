# libtraceroute.py
#
# (c) 2018 Marco Starke
#
#
# Traceroute module to traceroute target hosts.
# Option to simulate Paris-Traceroute/Dublin-Traceroute (Multipath Detection Algorithm, MDA)
#
# https://paris-traceroute.net
# https://hal.inria.fr/hal-01097558/file/e2emon2007.pdf
# https://hal.inria.fr/hal-01097562/document
#
# https://dublin-traceroute.net


import multiprocessing
import ipaddress
import socket

import libconstants as const
import libalgorithm
import libtools
import liblog
log = liblog.get_root_logger()


class TracerouteException(Exception):
  pass


class Traceroute(object):
  """
  Takes a hostname or an IP (v4/v6) address as traceroute destination.
  Works with ipaddress.IPv{4,6}Address class.

  Use 'ipversion' parameter to explicitly use IPv4 or IPv6 if hostname
  instead of IP address was provided (e.g. ipversion = libconstants.IP_VERSION_6)

  [Planned for Paris-/Dublin-Traceroute usage towards algorithm implementations]
  """

  def __init__(self, target, iface = 'en0', algorithm = 'traceroute', protocol = 'tcp', srcport = const.TR_TCP_DEFAULT_SRC_PORT, dstport = const.TR_TCP_DEFAULT_DST_PORT,
               min_ttl = 0, max_ttl = 30, timeout = 30, detect_broken_nat = False, ipversion = const.IP_VERSION_4):

    libtools.validate((type(target) in [str, ipaddress.IPv4Address, ipaddress.IPv6Address]),
        'Wrong type for [target], should be a string (hostname / IP address) [was \'{0}\']'.format(type(target)))
    libtools.validate((type(ipversion) is int and ipversion in [const.IP_VERSION_4, const.IP_VERSION_6]),
        'Illegal input, [ipversion] must be \'libconstants.IP_VERSION_4\' or \'libconstants.IP_Version_6\' [was \'{0}\']'.format(type(ipversion)))

    # parse string to IP address (v4/v6)
    address = libtools.get_IP_from_str(target, ipversion)
    if not address:
      raise TracerouteException('Input error, target is no IP address and no valid hostname. Could not resolve [{0}] to an IPv{1} address!'.format(target, ipversion))

    if not libtools.crosscheck_ip_version(address, ipversion):
      raise TracerouteException('Given IP address does not match given IP version!')

    # log.debug('Resolved target [{0}] to IPv{1}: {2}'.format(target, ipversion, address))

    self.ipaddress = address
    self.ipversion = ipversion
    self.iface = iface

    self.algorithm_str = algorithm
    self.protocol = protocol
    self.srcport = srcport
    self.dstport = dstport
    self.min_ttl = min_ttl
    self.max_ttl = max_ttl
    self.timeout = timeout
    # this parameter may be used in future algorithm implementations (dublin-traceroute)
    self.detect_broken_nat = detect_broken_nat

    # scapy parameters
    self.filter = None
    self.retry = 0
    self.multi = False
    self.store_unanswered = False

    # Initialize traceroute algorithm
    self.algorithm = libalgorithm.get_algorithm(algorithm)
    self.algorithm.init(algorithm_params = self)


  def start_trace(self):
    return self.algorithm.run()


  def start_traceroute(self):
    return self.algorithm.run()




class CPTraceroute(object):
  """
  CPTraceroute class to handle IPv4/IPv6 candidate pair traceroutes.
  Wrapper for single traceroute.
  """
  def __init__(self, target, iface = 'en0', algorithm = 'traceroute', protocol = 'tcp', srcport = const.TR_TCP_DEFAULT_SRC_PORT, dstport = const.TR_TCP_DEFAULT_DST_PORT,
               min_ttl = 0, max_ttl = 30, timeout = 30, detect_broken_nat = False):

    libtools.validate(((type(target) is tuple and len(target) == 2) or (type(target) is str)),
        'Wrong type for [target], should be a string (hostname) or a tuple of length 2 (IPv4, IPv6) [was \'{0}\']'.format(type(target)))
    libtools.validate((type(algorithm) is str and algorithm in const.ALGORITHMS_AVAILABLE),
        'Illegal input, [algorithm] should be string and one of \'{0}\', [was \'{1}\']'.format(str(const.ALGORITHMS_AVAILABLE), algorithm))
    libtools.validate(protocol in ('udp', 'tcp', 'icmp'),
        'Illegal input, [protocol] should be one of (\'udp\', \'tcp\', \'icmp\') [was \'{0}\']'.format(protocol))
    libtools.validate((type(min_ttl) is int and min_ttl >= 0 and min_ttl < 256),
        'Illegal input, [min_ttl] should be int and between 0 and 255 [was \'{0}\']'.format(min_ttl))
    libtools.validate((type(max_ttl) is int and max_ttl >= 0 and max_ttl < 256),
        'Illegal input, [max_ttl] should be int and between 0 and 255 [was \'{0}\']'.format(max_ttl))
    libtools.validate((min_ttl < max_ttl), 'Illegal input, min_ttl must be less than max_ttl')
    libtools.validate((type(timeout) is int and timeout <= 3600 and timeout >= 1),
        'Illegal input, [timeout] should be int and between 1 and 3600 seconds [was \'{0}\']'.format(timeout))

    if type(target) is str:
      addresses = libtools.resolve_host_dual(target)
      if not addresses:
        raise TracerouteException('Hostname \'{0}\' does not have an IPv4 or IPv6 address. In doubt provide a tuple \'(IPv4, IPv6)\'.'.format(target))
      self.ipv4, self.ipv6 = addresses
      self.hostname = target
    else:
      self.hostname = None
      self.ipv4 = ipaddress.ip_address(target[0])
      self.ipv6 = ipaddress.ip_address(target[1])

    self.traceroute_result4 = None
    self.traceroute_result6 = None

    # create IPv4 and IPv6 traceroute object
    self.tr4 = Traceroute(self.ipv4, iface, algorithm, protocol, srcport, dstport, min_ttl, max_ttl, timeout, detect_broken_nat, const.IP_VERSION_4)
    self.tr6 = Traceroute(self.ipv6, iface, algorithm, protocol, srcport, dstport, min_ttl, max_ttl, timeout, detect_broken_nat, const.IP_VERSION_6)

    if self.hostname:
      log.debug('CPTraceroute created for host \'{0}\' (IPv4: {1}, IPv6: {2})'.format(self.hostname, self.ipv4, self.ipv6))
    else:
      log.debug('CPTraceroute created for (IPv4: {0}, IPv6: {1})'.format(self.ipv4, self.ipv6))



  def traceroute(self, result_timeout = None):
    """
    Asynchronously traceroutes with given algorithm IPv4 and IPv6 targets.
    Use traceroute_running and traceroute_wait to wait for results.
    """

    with multiprocessing.Pool(processes = 2) as pool:
      log.debug('Started traceroute for IPv4 and IPv6 targets ...')

      res4 = pool.apply_async(self.tr4.start_trace)
      res6 = pool.apply_async(self.tr6.start_trace)

      # raises multiprocessing.TimeoutError if timeout happens after 'timeout' seconds
      try:
        self.v4trace, self.traceroute_result4 = res4.get(timeout = result_timeout)
      except multiprocessing.TimeoutError:
        log.error('Timeout during IPv4 traceroute! Increase existing timeout ({0} seconds) or check trace manually!'.format(result_timeout))
        self.v4trace = None
      except Exception as e:
        log.error('Exception: {0} - {1}'.format(type(e).__name__, e)) # prevents KeyError in traceroute algorithm if target IP is not in result set
        self.v4trace = None

      try:
        self.v6trace, self.traceroute_result6 = res6.get(timeout = result_timeout)
      except multiprocessing.TimeoutError:
        log.error('Timeout during IPv6 traceroute! Increase existing timeout ({0} seconds) or check trace manually!'.format(result_timeout))
        self.v6trace = None
      except Exception as e:
        log.error('Exception: {0} - {1}'.format(type(e).__name__, e)) # prevents KeyError in traceroute algorithm if target IP is not in result set
        self.v6trace = None

      if not self.v4trace or not self.v6trace:
        return (None, None)

      log.debug('Finished traceroute!')

      self.v4length = len(self.v4trace)
      self.v6length = len(self.v6trace)

      if self.v4length != self.v6length:
        log.debug('Traces differ in length, v4 trace [{0}], v6 trace [{1}]'.format(self.v4length, self.v6length))
      else:
        log.debug('Traces have identical length [{0}]'.format(self.v4length))

      return (self.v4trace, self.v6trace)


  def get_traceroute_results(self):
    return (self.traceroute_result4, self.traceroute_result6)


  def dump_traces(self, filename = None, include_src = True, include_dst = True):
    import prettytable
    import itertools

    rows = itertools.zip_longest(self.v4trace.values(), self.v6trace.values(), fillvalue = '')

    table = prettytable.PrettyTable(['Hop', 'IPv4 Trace', 'IPv6 Trace'])

    # include source
    if include_src:
      try:
        v4src = const.IFACE_IP4_ADDRESS # self.traceroute_result4.res[0][0].src
        v6src = const.IFACE_IP6_ADDRESS # self.traceroute_result6.res[0][0].src
        table.add_row((0, v4src, v6src))
        table.add_row(('--', '----', '----'))
      except:
        pass

    last_hop = 0
    for i, row in enumerate(rows, start = 1):
      v4, v6 = row
      r = (i, v4, v6)
      table.add_row(r)
      last_hop = i

    # include destination
    if include_dst:
      table.add_row(('--', '----', '----'))
      dst = (str(last_hop + 1), str(self.ipv4), str(self.ipv6))
      table.add_row(dst)

    if filename:
      log.debug('Writing traceroute table to file {0}'.format(filename))
      with open(filename, "a+") as out:
        out.write(str(table) + '\n')

    return table
