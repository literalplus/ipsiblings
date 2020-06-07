# libtools.py
#
# (c) 2018 Marco Starke
#


"""
Tools module to provide several utility functions including validation functions.

"""

import os
import io
import re
import csv
import errno
import ipaddress
import netifaces
import socket
import threading
import zipfile
import urllib.request
import collections

import scapy.all as scapy


from . import libconstants as const
from . import liblog
log = liblog.get_root_logger()


### CLASSES ###
###############

class ResetTimer(threading.Thread):
  # found at
  # https://code.activestate.com/recipes/577407-resettable-timer-class-a-little-enhancement-from-p/
  """
  Call a function after a specified number of seconds:

  t = ResetTimer(10, f, args = None, kwargs = None)
  t.start()
  t.reset(interval = 20) # reset the timer with new interval
  t.cancel() # stop the timer's action if it's still waiting

  Parameters:

  interval          wait 'interval' seconds until function is called
  synchronization   for multiprocessing purposes a shared Event object must be provided (managed)
  functions         function which should be called after 'interval' seconds
  """
  def __init__(self, interval, synchronization, function, args = None, kwargs = None):
    threading.Thread.__init__(self)
    self.interval = interval * 1.0 if interval else None # ensure floating point
    self.function = function
    self.args = args if args is not None else []
    self.kwargs = kwargs if kwargs is not None else {}
    self.finished = synchronization # threading.Event()
    self.finished.clear() # initial clear
    self.resetted = True

  def cancel(self):
    """Stop the timer if it hasn't finished yet."""
    self.finished.set()

  def run(self):
    while self.resetted:
      self.resetted = False
      timeout = not self.finished.wait(self.interval)

    if not self.finished.is_set() and timeout: # only call if timeout REALLY happened
      self.function(*self.args, **self.kwargs)

    self.finished.set()

  def reset(self, interval = None):
    if interval:
      self.interval = interval

    self.resetted = True
    self.finished.set()
    self.finished.clear()


class Trie():
  #author:         rex
  #blog:           http://iregex.org
  #filename        trie.py
  #created:        2010-08-01 20:24
  #source uri:     http://iregex.org/blog/trie-in-python.html

  # Trie <=> PrefixTree or RadixTree (ordered tree)

  """
  Python regex trie. Creates a Trie out of a list of words (e.g. IP addresses).
  The trie can be exported to a regex pattern.
  The corresponding regex should match much faster than a simple regex union.

  Example:

  def trie_regex(items):
    trie = Trie()
    for item in items:
      trie.add(item)
    return re.compile(r'^' + trie.pattern(), re.IGNORECASE)

  def ignore(item, regex):
    return regex.match(item)


  union = trie_regex(items_to_match)

  for string in big_item_list:
    do_something_with(ignore(string, union))
  """

  def __init__(self):
    self.data = {}

  def add(self, word):
    ref = self.data
    for char in word:
      ref[char] = char in ref and ref[char] or {}
      ref = ref[char]
    ref[''] = 1

  def dump(self):
    return self.data

  def quote(self, char):
    return re.escape(char)

  def _pattern(self, pData):
    data = pData
    if '' in data and len(data.keys()) == 1:
      return None

    alt = []
    cc = []
    q = 0
    for char in sorted(data.keys()):
      if isinstance(data[char], dict):
        try:
          recurse = self._pattern(data[char])
          alt.append(self.quote(char) + recurse)
        except:
          cc.append(self.quote(char))
      else:
        q = 1
    cconly = not len(alt) > 0

    if len(cc) > 0:
      if len(cc) == 1:
        alt.append(cc[0])
      else:
        alt.append('[' + ''.join(cc) + ']')

    if len(alt) == 1:
      result = alt[0]
    else:
      result = '(?:' + '|'.join(alt) + ')'

    if q:
      if cconly:
        result += '?'
      else:
        result = '(?:{0})?'.format(result)
    return result

  def pattern(self):
    return self._pattern(self.dump())


class SentinelList(collections.UserList):
  # This class shows how attributes of parent classes can be hidden from
  # subclasses by using '__getattribute__' and '__dir__' functions.
  # -> https://medium.com/@maouu/sorry-but-youre-wrong-aea1b88ffc03
  def __getattribute__(self, name):
    excluded = ['__mul__', '__imul__', '__rmul__', 'copy', 'pop']
    if name in excluded:
      raise NotImplementedError(name) # raise AttirbuteError(name)
    else:
      return super().__getattribute__(name)

  def __dir__(self):
    excluded = ['__mul__', '__imul__', '__rmul__', 'copy', 'pop']
    return sorted( (set(dir(self.__class__)) | set(self.__dict__.keys())) - set(excluded))


  def __init__(self, *args, **kwargs):
    """
    Extends collections.UserList and adds a sentinel member.
    """
    super().__init__(*args, **kwargs)
    self.__modified = False

  @property
  def modified(self):
    return self.__modified

  def reset_modified(self):
    """
    Set current data state to initial state (modification is tracked from now on)
    """
    self.__modified = False

  def __setitem__(self, i, item):
    super().__setitem__(i, item)
    self.__modified = True

  def __delitem__(self, i):
    super().__delitem__(i)
    self.__modified = True

  def __add__(self, other):
    instance = super().__add__(other)
    self.__modified = True
    return instance

  def __radd__(self, other):
    instance = super().__radd__(other)
    self.__modified = True
    return instance

  def __iadd__(self, other):
    instance = super().__iadd__(other)
    self.__modified = True
    return instance

  def append(self, item):
    super().append(item)
    self.__modified = True

  def insert(self, i, item):
    super().insert(i, item)
    self.__modified = True

  # def pop(self, i = -1): # excluded to show how attributes can be removed from subclasses
  #   val = super().pop(i)
  #   self.__modified = True
  #   return val

  def remove(self, item):
    super().remove(item)
    self.__modified = True

  def clear(self):
    super().clear()
    self.__modified = True

  # def copy(self): # excluded to show how attributes can be removed from subclasses
  #   return super().copy()

  def reverse(self):
    super().reverse()
    self.__modified = True

  def sort(self, *args, **kwargs):
    super().sort(*args, **kwargs)
    self.__modified = True

  def extend(self, other):
    super().extend(other)
    self.__modified = True


class SentinelDict(collections.UserDict):

  def __init__(self, *args, **kwargs):
    """
    Extends collections.UserDict and adds a modified boolean property.
    If __delitem__ or __setitem__ are called, modified is set to True.
    Be aware that other modification methods do not track at the moment!
    """
    super().__init__(*args, **kwargs)
    self.__modified = False

  def get(self, key):
    return self.__getitem__(key)

  def __setitem__(self, key, value):
    super().__setitem__(key, value) # self.data[key] = item
    self.__modified = True

  def set(self, key, value):
    self.__setitem__(key, value)

  def __delitem__(self, key):
    super().__delitem__(key) # del self.data[key]
    self.__modified = True

  @property
  def modified(self):
    return self.__modified

  def reset_modified(self):
    """
    Set current data state to initial state (modification is tracked from now on)
    """
    self.__modified = False


### VALIDATION ###
##################

def validate(condition: bool, msg: str):
  """
  Assertion style input validation
  """
  if not condition:
    raise ValueError(msg)


### NETWORK ###
###############

def get_dualstack_nics():
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
        try: # prevent errors while parsing IPv4 address
          if ipaddress.ip_address(addresses['addr']).is_global:
            has_ipv4 = True
            break # we have a valid global IPv4 address -> break
        except:
          continue
    else: # interface does not have an IPv4 address
      continue

    if netifaces.AF_INET6 in netifaces.ifaddresses(nic):
      for addresses in netifaces.ifaddresses(nic)[netifaces.AF_INET6]:
        try: # scoped addresses (e.g. 'fe80::be76:4eff:fe10:5b8d%eth0') do not work of course
          if ipaddress.ip_address(addresses['addr'].split('%')[0]).is_global: # so split off the scope
            has_ipv6 = True
            break # we have a valid global IPv6 address -> break
        except:
          continue
    else: # interface does not have an IPv6 address
      continue

    if has_ipv4 and has_ipv6:
      dual_stack_nics.append(nic)

  dual_stack_nics.sort()

  return dual_stack_nics


def get_host_by_ip(ip, verbose = False):
  """
  Returns (name, aliaslist, addresslist) or None on error.
  """
  try:
    return socket.gethostbyaddr(ip)
  except (socket.error, socket.herror, socket.gaierror, socket.timeout) as e:
    if verbose:
      log.debug('Hostname error for [{0}]: '.format(ip) + str(e))
    return None


def get_mac(iface = 'en0'):
  try:
    return netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
  except Exception as e:
    log.warning('Exception: {0}'.format(str(e)))
    return ''


def get_iface_IPs(iface = 'en0'):

  v4addr = None
  v6addr = None

  try:
    ifaddr = netifaces.ifaddresses(iface)

    if netifaces.AF_INET in ifaddr.keys():
      links = ifaddr[netifaces.AF_INET]
      for link in links:
        if 'addr' in link.keys() and 'peer' not in link.keys(): # exclude 'peer' (loopback address)
          v4addr = link['addr']

    if netifaces.AF_INET6 in ifaddr.keys():
      links = ifaddr[netifaces.AF_INET6]
      for link in links:
        if 'addr' in link.keys() and link['addr'].startswith('2'): # only global
          v6addr = link['addr']
  except:
    pass

  return (v4addr, v6addr)


def resolve_host(hoststr, ipversion = const.IP_VERSION_4):
  """
  Resolves hoststr to first listed (based on DNS) IP address of ipversion.
  """
  address = None

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

  return (ipaddress.ip_address(addrv4), ipaddress.ip_address(addrv6))


def parse_IP(target):
  """
  Returns ipaddress.ip_address(target), None otherwise.
  """
  try:
    address = ipaddress.ip_address(target)
  except ValueError:
    return None

  return address


def get_IP_from_str(hoststr, ipversion = const.IP_VERSION_4):
  """
  Returns ipaddress.IPv{4,6}Address or None if error occurred.
  If hoststr is either a valid IPv4 or IPv6, ipversion parameter is ignored!
  """
  address = parse_IP(hoststr)
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


def is_global(ip, ipversion = None):
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
      try:
        addr.ipaddress.ip_address(ip)
      except:
        return None
      return addr.is_global and (ip.startswith('2') or ip.startswith('3'))

  else: # determine ip version
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


def get_global_ip_addresses(traces, as_set = False):
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
    return (v4list, v6list)


### PACKET MANIPULATION ###
###########################

def reply_tcp_RA(dst, dport, sport, ipversion = const.IP_VERSION_4):
  p = scapy.Ether()
  if ipversion is const.IP_VERSION_4:
    p = p/scapy.IP(dst = dst)
  elif ipversion is const.IP_VERSION_6:
    p = p/scapy.IPv6(dst = dst)
  else:
    raise ValueError('Illegal IP version detected [{0}]!'.format(str(ipversion)))

  p = p/scapy.TCP(dport = dport, sport = sport, flags = 'RA')
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
  except Excepiton as e:
    log.error('Exception: {0}'.format(str(e)))

  return None



### FILE IO ###
###############

def write_constructed_pairs(filename, data, include_domain = False):
  nr_records = 0
  with open(filename, mode = 'w') as outfile:
    if include_domain:
      for record in data:
        domains, ip4, ip6 = record
        if is_iterable(domains):
          domains = ','.join(domains)
        outfile.write('{0};{1};{2}\n'.format(ip4, ip6, domains))
        nr_records = nr_records + 1
    else:
      for record in data:
        ip4, ip6 = record
        outfile.write('{0};{1}\n'.format(ip4, ip6))
        nr_records = nr_records + 1

  return nr_records


def create_directories(file_or_dir):
  """
  Create all underlying directories if they do not exist.
  Returns False on error (but None if the directory was created during call).
  If the directory already exists None is returned.
  True, if successfully created.
  """
  directory = os.path.dirname(file_or_dir)
  if not os.path.exists(directory):
    try:
      os.makedirs(directory)
    except OSError as e: # race condition guard
      if e.errno != errno.EEXIST:
        log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
        return False
      else: # directory was created during call
        return None
    else:
      return True
  else:
    return None

# expected format:
# 10.0.0.1
# # this is a comment
# 192.168.*
# =
# 2001:f80::1337:42
#
def parse_ignore_file(file):
  """
  File structure:
  IPv4 address
  IPv4 address
  ...
  =
  IPv6 address
  ...

  The input file can use '#' for comments.
  A line starting with '=' signals the start of IPv6 addresses.
  '10.*' may be used to ignore all addresses starting with '10.x.x.x'.
  Empty lines will be ignored.
  """

  v4addresses = []
  v6addresses = []

  regex = re.compile('^([0-9]|[f:])')

  with open(file, "r") as ignore_file:
    tmp_list = v4addresses
    for l in ignore_file:
      line = l.strip().lower()
      if not line or line.startswith("#"):
        continue
      if line.startswith("="):
        tmp_list = v6addresses
        continue

      if re.match(regex, line):
        tmp_list.append(line)


  return (v4addresses, v6addresses)


def apply_ignore_file(addresses, fname):
  """
  Returns a tuple with two lists.
  Those lists hold 'addresses' excluding IPs contained in 'fname'.
  """
  # Found at: https://stackoverflow.com/a/42789508
  # With sets: https://stackoverflow.com/a/42747503

  v4ignore, v6ignore = parse_ignore_file(fname)

  trie = Trie()
  for v4a in v4ignore:
    a = v4a.strip().strip('*').lower()
    trie.add(a)
  v4regex = re.compile(r'^' + trie.pattern(), re.IGNORECASE)

  trie = Trie()
  for v6a in v6ignore:
    a = v6a.strip().strip('*').lower()
    trie.add(a)
  v6regex = re.compile(r'^' + trie.pattern(), re.IGNORECASE)

  v4addresses = []
  v6addresses = []

  if not v4ignore:
    v4addresses = addresses[0]
  else:
    for a in addresses[0]:
      if not v4regex.match(a):
        v4addresses.append(a)

  if not v6ignore:
    v6addresses = addresses[1]
  else:
    for a in addresses[1]:
      if not v6regex.match(a):
        v6addresses.append(a)

  return (v4addresses, v6addresses)


def construct_blacklist_regex(filename):
  """
  Returns the compiled regex objects constructed from the given file.
  """
  if not filename:
    return (None, None)

  v4ignore, v6ignore = parse_ignore_file(filename)

  trie = Trie()
  for v4a in v4ignore:
    a = v4a.strip().strip('*').lower()
    trie.add(a)
  v4regex = re.compile(r'^' + trie.pattern(), re.IGNORECASE)

  trie = Trie()
  for v6a in v6ignore:
    a = v6a.strip().strip('*').lower()
    trie.add(a)
  v6regex = re.compile(r'^' + trie.pattern(), re.IGNORECASE)

  return (v4regex, v6regex)



# Determines IPv4/IPv6 indices automatically with the ipaddress module
# Scheitle et al. 2017 format:
# host_name;asn;asn_v4;asn_v6;country_code;address_v4;address_v6
# https://stackoverflow.com/a/904085
def parsecsv(fname, delimiter = ';', iponly = True, include_domain = False):
  """
  Parse csv file to a list: [ (IPv4, IPv6), (IPv4, IPv6), ... ]
  If include_domain is given, the domain must be always on first position in the file!

  If 'iponly' is False additional information is parsed:
  [ (IPv4, IPv6), remaining, data, as, list, items ]

  fname           file to parse
  delimiter       optional (';')
  iponly          optional (True) returns a list of tuples containing (IPv4, IPv6) pairs
  include_domain  optional (False) in combination with iponly returns (domain, IPv4, IPv6)
                  domain must be the first position in each row (index 0)
  """
  ip4index = None
  ip6index = None

  candidate_list = []
  with open(fname, newline = '', encoding = 'utf-8') as csvfile:
    csvreader = csv.reader(csvfile, delimiter = delimiter)

    # to ignore the header we may have to inspect the 2nd row to identify indices
    for i in range(2):
      if ip4index and ip6index: # if no header is present this must be checked to not miss the first data row
        break # no header present, we already identified both indices
      row = next(csvreader)
      # determine ip4 and ip6 column index in csv file
      for pos, item in enumerate(row):
        try:
          ip = ipaddress.ip_address(item)
          if ip.version == 4:
            ip4index = pos
          elif ip.version == 6:
            ip6index = pos
        except:
          pass

    if ip4index is None or ip6index is None:
      raise ValueError('Could not determine indices for IP addresses!')

    # add first entry manually
    # use ipaddress module to standardize IPv6 address strings
    ip4, ip6 = row[ip4index], str(ipaddress.ip_address(row[ip6index]))
    if iponly:
      if include_domain: # must be always at index 0 in each row
        record = (row[0], ip4, ip6)
      else:
        record = (ip4, ip6)
    else:
      record = [row[i] for i, e in enumerate(row) if i not in [ip4index, ip6index]]
      record.insert(0, (ip4, ip6))

    candidate_list.append(record)


    for row in csvreader:
      # use ipaddress module to standardize IPv6 address strings
      ip4, ip6 = row[ip4index], str(ipaddress.ip_address(row[ip6index]))

      if iponly:
        if include_domain: # must be always at index 0 in each row
          record = (row[0], ip4, ip6)
        else:
          record = (ip4, ip6)
      else:
        record = [row[i] for i, e in enumerate(row) if i not in [ip4index, ip6index]]
        record.insert(0, (ip4, ip6))

      candidate_list.append(record)

  return candidate_list



### ALEXA TOP LIST ###
######################

def load_alexa_top_list(url = const.ALEXA_URL, filename = const.ALEXA_FILE_NAME):
  """
  Loads the Alexa Top Million List from the given url and returns
  a generator yielding each domain name in ascending order.
  If no url is given libconstants.ALEXA_URL is used.
  http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
  If no filename is given libconstants.ALEXA_FILE_NAME is used (top-1m.csv).
  """
  # top-1m.csv structure:
  # position,domain
  httpresponse = urllib.request.urlopen(url)
  with zipfile.ZipFile(io.BytesIO(httpresponse.read())) as zf:
    with zf.open(filename) as csvfile:
      for line in csvfile.readlines():
        yield line.decode('utf-8') # .split(',')[0] # domain only


def resolve_top_list_records(top_list, filename = None):
  resolved = []

  for entry in top_list:
    pos, domain = entry.split(',')
    ips = libtools.resolve_host_dual(domain)
    if not ips:
      continue

    record = (pos, domain, str(ips[0]), str(ips[1]))
    resolved.append(record)

  if filename:
    with open(filename, mode = "w") as out:
      for record in resolved:
        out.write(','.join(record))
        out.write('\n')

  return resolved



### MISC ###
############

def is_iterable(obj):
  """
  Considers only non-string types as iterables
  """
  return (isinstance(obj, collections.Iterable) and not isinstance(obj, str))


def split_list(l, n):
  """
  Splits list l into chunks of size n. Returns a generator.
  """
  # https://stackoverflow.com/a/312464
  for i in range(0, len(l), n):
    yield l[i:i + n]
