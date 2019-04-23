# libtrace.py
#
# (c) 2018 Marco Starke
#


"""
Module which handles interaction with Trace classes.
"""

import collections
import prettytable
import itertools
import hashlib
import scapy.all as scapy
import csv
import os
import errno
import glob


import libconstants as const
import libtools
import liblog
log = liblog.get_root_logger()


class TraceSet(object):
  """
  Routes may differ for the same destination.
  Holds different Trace objects and the (only one) TraceData.

  Acts as a wrapper for the TraceData object.
  """

  def __init__(self, target = None, domain = None):
    """
    If target and domain is None initialization must be done by loading from file.
    If target is None and domain is given, try to resolve IPv4 and IPv6 address for the given domain.
    Raise ValueError exception if not both IP version addresses available.

    target  ( str(v4target), str(v6target) ) or None
    domain  string or None
    """
    self.target = target
    self.domain = domain
    self.traces = {}
    self.trace_data = TraceData()

    self.active_nodes4 = None
    self.active_nodes6 = None
    self.number_active_nodes4 = None
    self.number_active_nodes6 = None

    if self.domain and not libtools.is_iterable(self.domain) and not self.target:
      t = libtools.resolve_host_dual(self.domain)
      if t:
        self.target = (str(t[0]), str(t[1]))
      else:
        log.error('Only one IP version available!')
        raise ValueError('Missing IP version! Can not retrieve A or AAAA record for \'{0}\''.format(self.domain))


    if self.target:
      self.traceset_id = self._id()
      self.tcp_sequence = self._tcp_seq()
    else:
      self.traceset_id = None
      self.tcp_sequence = None

  def __str__(self):
    string_list = []
    string_list.append('Trace Set ID: {0} - Traces: {1}'.format(self.traceset_id, str(len(self.traces))))
    for id, trace in self.traces.items():
      string_list.append('Trace ID: {0}\n{1}'.format(id,str(trace)))

    return '\n\n'.join(string_list)

  # python3 no longer requires to implement __ne__
  # calls __eq__ and inverts result when using !=
  def __eq__(self, other):
    if isinstance(other, TraceSet):
      if self.traceset_id and other.traceset_id:
        return self.traceset_id == other.traceset_id

    return NotImplemented

  def _id(self):
    str_to_hash = '{0}_{1}'.format(self.target[0], self.target[1])
    h = hashlib.md5()
    h.update(str_to_hash.encode('utf-8'))
    return h.hexdigest()

  def _tcp_seq(self):
    return int(self.traceset_id[:8], 16) # first 32bit

  def id(self):
    return self.traceset_id

  def tcp_seq(self):
    return self.tcp_sequence

  def get_target(self):
    return self.target

  def get_domain(self):
    return self.domain

  def get_traces(self):
    return self.traces

  def get_trace_data_object(self):
    return self.trace_data

  def get_trace_data(self):
    return self.trace_data.data()

  def get_tcp_options(self):
    return self.trace_data.tcpoptions()

  def get_active_nodes(self):
    """
    Returns the active nodes from this trace set.
    Caches the result.
    -> ( { IPv4: { portlist } }, { IPv6: { portlist } } )
    """
    if self.active_nodes4 and self.active_nodes6 and self.number_active_nodes4 and self.number_active_nodes6:
      return (self.active_nodes4, self.active_nodes6)

    v4nodes = {}
    v6nodes = {}

    for trace in self.traces.values():
      an = trace.get_active_nodes()
      for ip, portlist in an[0].items():
        if ip in v4nodes:
          v4nodes[ip].update(portlist)
        else:
          v4nodes[ip] = set(portlist)

      for ip, portlist in an[1].items():
        if ip in v6nodes:
          v6nodes[ip].update(portlist)
        else:
          v6nodes[ip] = set(portlist)

    self.number_active_nodes4 = len(v4nodes)
    self.number_active_nodes6 = len(v6nodes)
    self.active_nodes4 = v4nodes
    self.active_nodes6 = v6nodes

    return (v4nodes, v6nodes)


  def get_number_of_active_nodes(self):
    """
    Returns number of active nodes.
    Caches the result.
    -> ( #IPv4, #IPv6 )
    """
    if not self.number_active_nodes4 or not self.number_active_nodes6:
      self.get_active_nodes() # cache the result to return # active nodes

    return (self.number_active_nodes4, self.number_active_nodes6)


  def add_trace(self, trace):
    if isinstance(trace, Trace):
      if trace.id() not in self.traces:
        self.traces[trace.id()] = trace
        return True
      else:
        return False
    log.debug('Argument is not a Trace object: {0}'.format(str(trace)))
    return False

  def add_record(self, ip, port, timestamps, tcp_options, ipversion = None):
    return self.trace_data.add_record(ip, port, timestamps, tcp_options = tcp_options, ipversion = ipversion)

  def add_records(self, records):
    return self.trace_data.add_records(records)

  def from_file(self, directory, v4bl_re = None, v6bl_re = None, iface = None):
    if not os.path.exists(os.path.dirname(directory)):
      log.error('Directory {0} does not exist!'.format(directory))
      return None

    targetfile = os.path.join(directory, 'target.txt')
    with open(targetfile, "r") as infile:
      v4target = infile.readline().strip()
      v6target = infile.readline().strip()
      self.domain = infile.readline().strip()
      self.target = (v4target, v6target)

    self.traceset_id = self._id()
    self.tcp_sequence = self._tcp_seq()
    # assert self.traceset_id == os.path.basename(os.path.normpath(directory))
    # assert abs(self.tcp_sequence) <= 0xffffffff # check 32 bit

    trace_files = [ fn for fn in glob.glob(os.path.join(directory, 'trace_*.txt')) if not 'active_nodes' in fn ]
    trace_active_nodes_files = [ fn for fn in glob.glob(os.path.join(directory, 'trace_*.txt')) if 'active_nodes' in fn ]

    # ensure that all active nodes get assigned to the correct trace
    trace_files.sort()
    trace_active_nodes_files.sort()

    # debug output
    # for tf, antf in zip(trace_files, trace_active_nodes_files):
    #   print(tf.split('/')[4], antf.split('/')[4]) # index is based on directory tree

    for tf, antf in zip(trace_files, trace_active_nodes_files):
      trace_obj = Trace().from_file(tf, v4bl_re = v4bl_re, v6bl_re = v6bl_re, iface = iface)
      trace_obj.active_nodes_from_file(antf)

      self.traces[trace_obj.id()] = trace_obj

    data_file = os.path.join(directory, 'data.txt')

    if os.path.isfile(data_file):
      self.trace_data.from_file(data_file)
    else:
      log.debug('No trace data available: {0}'.format(data_file))

    tcp_opt_file = os.path.join(directory, 'tcp_options.txt')

    if os.path.isfile(tcp_opt_file):
      self.trace_data.from_file_tcp_options(tcp_opt_file)
    else:
      log.debug('No TCP options data available: {0}'.format(tcp_opt_file))


  def to_file(self, base_directory, write_target = True, write_traces = True, write_trace_data = True):
    """
    Create a directory in base_directory named '${traceset_id}'.
    In this directory the following files will be written: 'target.txt', 'trace_[trace_id].txt', 'trace_[trace_id].active_nodes.txt', 'trace_[trace_id].active_nodes.txt.pcap' and 'data.txt'.
    Depending on the flags given:
    write_target -> target.txt
    write_traces -> trace_*.txt, trace_*.active_nodes.txt, trace_*.active_nodes.txt.pcap
    write_trace_data -> data.txt
    """
    directory = os.path.join(base_directory, self.traceset_id, '')
    dir_status = libtools.create_directories(directory)
    if dir_status is None:
      log.debug('Directory [{0}] already exists'.format(directory))
    elif dir_status == False: # only if OSError != errno.EEXist
      log.error('Error while creating directory [{0}] - Aborting ...'.format(directory))
      return

    if write_target:
      targetfile = os.path.join(directory, 'target.txt')
      with open(targetfile, mode = "w") as outfile:
        outfile.write(self.target[0])
        outfile.write('\n')
        outfile.write(self.target[1])
        outfile.write('\n')
        if self.domain:
          outfile.write(self.domain)
        outfile.write('\n')

    if write_traces:
      for id, trace in self.traces.items():
        trace.to_file(os.path.join(directory, 'trace_{0}.txt'.format(id)))
        trace.active_nodes_to_file(os.path.join(directory, 'trace_{0}.active_nodes.txt'.format(id)))

    if write_trace_data:
      self.trace_data.to_file(os.path.join(directory, 'data.txt'))
      self.trace_data.to_file_tcp_options(os.path.join(directory, 'tcp_options.txt'))


  def write_timestamp_data(self, base_directory):
    self.to_file(base_directory, write_target = False, write_traces = False, write_trace_data = True)


  def has_timestamp_data(self):
    return self.trace_data.has_timestamp_data()


  def has_candidates(self):
    # a trace can have ip4 nodes but another trace can have ip6 nodes (same target!)
    has_ip4 = any([trace.has_ip4_candidates() for trace in self.traces.values()])
    has_ip6 = any([trace.has_ip6_candidates() for trace in self.traces.values()])

    if has_ip4 and has_ip6:
      return True

    return False




class TraceData(object):
  """
  Holds the collected timestamps of all responding IP/Port combinations of Traces.

  data => { 4: { IPv4: { port: [timestamps] } }, 6: { IPv6: { port: [timestamps] } } }
  tcp_options => { IP: scapy.TCP_options }
  """

  def __init__(self):
    self.trace_data = { 4: {}, 6: {} }
    self.tcp_options = {}


  def data(self):
    return self.trace_data

  def tcpoptions(self):
    return self.tcp_options


  def has_timestamp_data(self):
    return self.trace_data[4] and self.trace_data[6]


  def add_record(self, ip, port, timestamps = [], tcp_options = None, ipversion = None):
    """
    Add a single record.

    timestamps -> [(remote_ts, received_ts)]
    tcp_options -> TCP options as provided by scapy
    """
    if type(timestamps) != list:
      timestamps = [timestamps]

    ip_version = ipversion if ipversion else libtools.parse_IP(ip).version

    data = self.trace_data[ip_version]
    if ip in data:
      if port in data[ip]:
        data[ip][port].extend(timestamps)
      else:
        data[ip][port] = timestamps
    else:
      data[ip] = { port: timestamps }

    if ip not in self.tcp_options:
      self.tcp_options[ip] = tcp_options



  def add_records(self, records):
    """
    Add multiple records at once.
    Required data structure:
    ( { IPv4: { port: [ (remote_ts, received_ts) ] } }, { IPv6: { port: [ (remote_ts, received_ts) ] } } )
    """
    recs = None
    for ipversion in [4, 6]:
      tracedata = self.trace_data[ipversion]
      if ipversion == 4:
        recs = records[0]
      else:
        recs = records[1]

      for ip, ts_data in recs.items():
        if ip in tracedata:
          for port, timestamps in ts_data.items():
            if port in recs[ip]:
              recs[ip][port].extend(timestamps)
            else:
              recs[ip][port] = timestamps
        else:
          tracedata[ip] = ts_data


  def from_file(self, filename, delimiter = ','):

    with open(filename, mode = "r", newline = '') as csvfile:
      csvreader = csv.reader(csvfile, delimiter = delimiter)

      data = self.trace_data[4] # start with ip4 data

      # use simple state machine
      # 0: read IP, 1: read port and timestamps
      state = 0 # start with reading IP address
      current_ip = None

      for row in csvreader:
        if not row: # go on with next IP address
          state = 0
          continue

        if row[0].startswith('='): # switch to IPv6 timestamps
          data = self.trace_data[6]
          state = 0
          continue

        if state == 0:
          current_ip = row[0]
          data[current_ip] = {}
          state = 1
          continue

        if state == 1:
          port = int(row[0])
          remote_ts = [ int(x) for x in row[1::2] ]
          received_ts = [ float(x) for x in row[2::2] ]
          timestamps = zip(remote_ts, received_ts)
          data[current_ip][port] = list(timestamps) # generator to list
          # stay in state 1 until empty row reached
          continue


  def to_file(self, filename, delimiter = ','):
    if not self.trace_data[4] and not self.trace_data[6]:
      # if no data is available do not create a file at all
      return None

    with open(filename, mode = "w") as outfile:
      data = None

      for ip_version in [4, 6]:
        data = self.trace_data[ip_version]

        if ip_version == 6:
          outfile.write('=\n\n')

        for ip, portlist in data.items():
          outfile.write(ip)
          outfile.write('\n')

          for port, timestamps in portlist.items():
            outfile.write(str(port))
            outfile.write(delimiter)
            outfile.write(delimiter.join(str(ts) for ts_tuple in timestamps for ts in ts_tuple)) # join the list of tuples into one string
            outfile.write('\n')

          outfile.write('\n')


  def from_file_tcp_options(self, filename, delimiter = ','):
    # row = [ip, opt1:val1, opt2:val2, opt3:val3.1:val3.2, opt4:val4]
    with open(filename, mode = "r", newline = '') as csvfile:
      csvreader = csv.reader(csvfile, delimiter = delimiter)

      for row in csvreader:
        ip = row[0]
        self.tcp_options[ip] = []
        for opt in row[1:]:
          name, *vals = opt.strip().split(':')
          values = []
          for v in vals:
            if v == 'None':
              values.append(None)
              continue
            values.append(v)
          if values:
            self.tcp_options[ip].append((name, tuple(values) if len(values) > 1 else values[0]))
          else:
            self.tcp_options[ip].append((name, None))


  def to_file_tcp_options(self, filename, delimiter = ','):
    if not self.tcp_options:
      return None

    with open(filename, mode = "w") as outfile:

      for ip, optionlist in self.tcp_options.items():
        outstring = [ip]
        for name, opt in optionlist:
          if libtools.is_iterable(opt):
            val_str = [name]
            for val in opt:
              val_str.append(str(val))
            outstring.append(':'.join(val_str))
          else:
            outstring.append('{0}:{1}'.format(name, opt))

        outfile.write('{0}\n'.format(delimiter.join(outstring)))




class Trace(object):
  """
  Represents an IPv4/IPv6 trace of a target.

  Identifies identical traces by using an ID created as follows:

  trace_id = md5(v4target, v6target, v4trace[], v6trace[], v4length, v6length)
  """

  def __init__(self):
    self.iface = None
    self.trace_id = None
    self.timestamps = None
    self.active_nodes = None
    self.active_nodes_packets = None
    self.active_nodes4_length = 0
    self.active_nodes6_length = 0

  def __str__(self):
    if self.trace_id is None:
      return '[Initialize with init() or initfile() first]'

    str_lst = []

    domainstr = "({0})".format(self.target_domain) if self.target_domain else ""
    table = prettytable.PrettyTable(['Hop', 'IPv4 Trace', 'IPv6 Trace'])

    if self.iface:
      str_lst.append("{0} / {1}\n==>>\n{2} / {3} {name}\n\n".format(self.v4src, self.v6src, self.v4target, self.v6target, name = domainstr))
      table.add_row((0, self.v4src, self.v6src))
      table.add_row(('--', '----', '----'))
    else:
      str_lst.append("==>>\n{0} / {1} {name}\n\n".format(self.v4target, self.v6target, name = domainstr))

    rows = itertools.zip_longest(self.v4trace, self.v6trace, fillvalue = '')

    last_hop = 0
    for i, row in enumerate(rows, start = 1):
      v4, v6 = row
      r = (i, v4, v6)
      table.add_row(r)
      last_hop = i

    table.add_row(('--', '----', '----'))
    dst = (str(last_hop + 1), str(self.v4target), str(self.v6target))
    table.add_row(dst)

    str_lst.append(str(table))

    return ''.join(str_lst)


  # python3 no longer requires to implement __ne__
  # calls __eq__ and inverts result when using !=
  def __eq__(self, other):
    if isinstance(other, Trace):
      return self.trace_id == other.trace_id
    else:
      return NotImplemented


  def _id(self):
    h = hashlib.md5()
    h.update(self.v4target.encode('utf-8'))
    h.update(self.v6target.encode('utf-8'))
    for ip in self.v4trace:
      h.update(ip.encode('utf-8'))
    for ip in self.v6trace:
      h.update(ip.encode('utf-8'))
    h.update(str(self.v4length).encode('utf-8'))
    h.update(str(self.v6length).encode('utf-8'))
    return h.hexdigest()


  def _load_timestamps(self, trace_data_obj):
    # data => { 4: { IPv4: { port: [timestamps] } }, 6: { IPv6: { port: [timestamps] } } }
    data = trace_data_obj.data()

    v4nodes = {}
    v6nodes = {}

    for ip in self.v4trace:
      if ip in data[4].keys():
        v4nodes[ip] = data[4][ip]

    for ip in self.v6trace:
      if ip in data[6].keys():
        v6nodes[ip] = data[6][ip]

    return (v4nodes, v6nodes)


  def init(self, v4target, v6target, v4trace, v6trace, domain = None, v4bl_re = None, v6bl_re = None, iface = None):
    """
    v4target  string
    v6target  string
    v4trace   iterable
    v6trace   iterable
    domain    string optional
    v4bl_re   v4 blacklist regex: compiled regex object optional
    v6bl_re   v6 blacklist regex: compiled regex object optional
    iface     dual stack interface to work with (used to determine v4 and v6 source addresses)
    """
    self.v4target = v4target
    self.v6target = v6target
    if isinstance(v4trace, dict):
      self.v4trace = v4trace.values()
    else:
      self.v4trace = v4trace
    if isinstance(v6trace, dict):
      self.v6trace = v6trace.values()
    else:
      self.v6trace = v6trace

    if not v4trace or not v6trace:
      raise ValueError('No Trace data available')

    self.v4length = len(v4trace)
    self.v6length = len(v6trace)

    self.target_domain = domain
    self.v4bl_re = v4bl_re
    self.v6bl_re = v6bl_re
    self.iface = iface
    self.v4src = const.IFACE_IP4_ADDRESS
    self.v6src = const.IFACE_IP6_ADDRESS
    # if self.iface:
    #   self.v4src, self.v6src = libtools.get_iface_IPs(iface = self.iface)

    self.trace_id = self._id()

    return self


  def initfile(self, filename, delimiter = ',', v4bl_re = None, v6bl_re = None, iface = None):
    """
    Reads from a csv constructed as follows:

    v4target [string]
    v6target [string]
    ipv4 trace (each hop one column)
    ipv6 trace (each hop one column)
    domain (optional, only valid if not empty)

    Only reads the first five lines of the file.

    v4bl_re   v4 blacklist regex: compiled regex object
    v6bl_re   v6 blacklist regex: compiled regex object
    iface     dual stack interface to work with (used to determine v4 and v6 source addresses)
    """

    with open(filename, mode = "r", newline = '') as csvfile:
      csvreader = csv.reader(csvfile, delimiter = delimiter)

      self.v4target = next(csvreader)[0]
      self.v6target = next(csvreader)[0]
      self.v4trace = next(csvreader)
      self.v6trace = next(csvreader)
      self.v4length = len(self.v4trace)
      self.v6length = len(self.v6trace)

      try:
        domain = next(csvreader)
        self.target_domain = domain[0] if domain else None
      except Exception as e:
        self.target_domain = None


    self.v4bl_re = v4bl_re
    self.v6bl_re = v6bl_re
    self.iface = iface
    self.v4src = const.IFACE_IP4_ADDRESS
    self.v6src = const.IFACE_IP6_ADDRESS
    # if self.iface:
    #   self.v4src, self.v6src = libtools.get_iface_IPs(iface = self.iface)

    self.trace_id = self._id()

    return self


  def id(self):
    """
    Returns unique ID after initialization with init() or initfile().
    Can be used for comparison.
    Additionally, compare by using '==' or '!='.
    """
    return self.trace_id


  def domain(self):
    """
    Returns the domain of the destination if available in trace file, otherwise None.
    """
    return self.target_domain


  def get_trace_lists(self):
    """
    Returns (list(v4trace), list(v6trace))
    """
    return (self.v4trace, self.v6trace)


  def get_global_valid_IPs(self, apply_ignore_regex = False):
    """
    Uses libtools.get_global_ip_addresses() to return traces only containing global IPs from the object's traces.
    If blacklist regex patterns were submitted to the init() function, they can be applied by setting
    'apply_ignore_regex' to True.
    """
    if apply_ignore_regex:
      v4whitelist = {}
      v6whitelist = {}

      for ttl, ip in enumerate(self.v4trace, start = 1):
        if not self.v4bl_re.match(ip):
          v4whitelist[ttl] = ip

      for hlim, ip in enumerate(self.v6trace, start = 1):
        if not self.v6bl_re.match(ip):
          v6whitelist[hlim] = ip

      addresses = libtools.get_global_ip_addresses((v4whitelist, v6whitelist))
    else:
      addresses = libtools.get_global_ip_addresses((self.v4trace, self.v6trace))

    return addresses


  def set_timestamps(self, trace_data_obj):
    """
    Loads ports and timestamps of IPs related to this Trace object from the given TraceData object.
    """
    self.timestamps = self._load_timestamps(trace_data_obj)


  def get_timestamps(self, trace_data_obj = None):
    """
    Returns the timestamps set before with 'set_timestamps()'.
    If trace_data_obj is given, ignore the class member and extract timestamps
    from the given trace_data_obj.
    ( { IPv4: { port: [timestamps] } }, { IPv6: { port: [timestamps] } } )
    """
    if trace_data_obj:
      return self._load_timestamps(trace_data_obj)
    else:
      return self.timestamps


  def set_active_nodes(self, ts_results):
    """
    Sets the the active nodes by using ts_results from initial timestamp query.
    active_nodes => ( { IPv4: [ ports ] } , { IPv6: [ ports ]  } )
    active_nodes_packets => ( { IPv4: { port: packet } }, { IPv6: { port: packet } } )
    """
    v4nodes = {}
    v6nodes = {}
    v4packets = {}
    v6packets = {}

    if ts_results[0]:
      for ip in ts_results[0]:
        v4nodes[ip] = list(ts_results[0][ip].keys())
        v4packets[ip] = { port: pkt_data[0][2] for port, pkt_data in ts_results[0][ip].items() } # index 2 -> scapy packet

    if ts_results[1]:
      for ip in ts_results[1]:
        v6nodes[ip] = list(ts_results[1][ip].keys())
        v6packets[ip] = { port: pkt_data[0][2] for port, pkt_data in ts_results[1][ip].items() }

    self.active_nodes4_length = len(v4nodes)
    self.active_nodes6_length = len(v6nodes)

    self.active_nodes = (v4nodes, v6nodes)
    self.active_nodes_packets = (v4packets, v6packets)


  def get_number_of_active_nodes(self):
    """
    Returns (nr of ip4 active nodes, nr of ip6 active nodes)
    """
    return (self.active_nodes4_length, self.active_nodes6_length)


  def get_active_nodes(self):
    """
    ( { IPv4: [ ports ] } , { IPv6: [ ports ]  } )
    """
    return self.active_nodes


  def get_active_nodes_packets(self):
    """
    ( { IPv4: { port: packet } }, { IPv6: { port: packet } } )
    """
    return self.active_nodes_packets


  def from_file(self, name, delimiter = ',', v4bl_re = None, v6bl_re = None, iface = None):
    return self.initfile(name, delimiter, v4bl_re, v6bl_re, iface)


  def to_file(self, name):
    with open(name, mode = "w") as outfile:
      outfile.write(self.v4target)
      outfile.write('\n')
      outfile.write(self.v6target)
      outfile.write('\n')
      outfile.write(','.join(self.v4trace))
      outfile.write('\n')
      outfile.write(','.join(self.v6trace))
      outfile.write('\n')

      if self.target_domain:
        outfile.write(self.target_domain)
        outfile.write('\n')


  def active_nodes_from_file(self, name, pcap_name = None):
    """
    If pcap_name is None 'name' + '.pcap' is used as file name.
    """
    v4nodes = {}
    v6nodes = {}
    v4packets = {}
    v6packets = {}

    with open(name, mode = "r", newline = '') as csvfile:
      csvreader = csv.reader(csvfile, delimiter = ',')
      nodes = v4nodes

      for row in csvreader:
        if not row:
          continue
        if row[0].startswith('='):
          nodes = v6nodes
          continue

        nodes[row[0]] = row[1:]

    self.active_nodes4_length = len(v4nodes)
    self.active_nodes6_length = len(v6nodes)

    self.active_nodes = (v4nodes, v6nodes)

    pcap = pcap_name if pcap_name else '{0}.pcap'.format(name)

    packetlist = scapy.rdpcap(pcap)
    # ( { IPv4: { port: packet } }, { IPv6: { port: packet } } )
    for p in packetlist: # packets contain Ether() layer
      version = p.payload.version
      ip = p.payload.src
      port = p.payload.payload.sport
      if version == const.IP_VERSION_4:
        v4packets[ip] = { port: p }
      elif version == const.IP_VERSION_6:
        v6packets[ip] = { port: p }
      else:
        log.error('Unknown packet: {0}'.format(p))

    self.active_nodes_packets = (v4packets, v6packets)


  def active_nodes_to_file(self, name, pcap_name = None):
    """
    Writes ( {IPv4: [ports]}, {IPv6: [ports]} ) to file:
    IPv4,port1,port2,port3, ...
    =
    IPv6,port1,port2,port3, ...

    Additionally writes active_nodes_packets to pcap file.
    If pcap_name is None 'name' + '.pcap' is used as file name
    """
    if self.active_nodes and not self.active_nodes[0] and not self.active_nodes[1]:
      # if no active nodes present do not create a file at all
      return None

    v4len = None
    v6len = None
    with open(name, mode = "w") as outfile:
      if self.active_nodes[0]:
        v4len = len(self.active_nodes[0])
        for ip, ports in self.active_nodes[0].items():
          outfile.write(ip)
          outfile.write(',')
          outfile.write(','.join([str(p) for p in ports]))
          outfile.write('\n')

      outfile.write('=\n')

      if self.active_nodes[1]:
        v6len = len(self.active_nodes[1])
        for ip, ports in self.active_nodes[1].items():
          outfile.write(ip)
          outfile.write(',')
          outfile.write(','.join([str(p) for p in ports]))
          outfile.write('\n')

    pcap = pcap_name if pcap_name else '{0}.pcap'.format(name)

    packetlist = []
    for ip, portdict in self.active_nodes_packets[0].items():
      packetlist.extend(portdict.values())
    for ip, portdict in self.active_nodes_packets[1].items():
      packetlist.extend(portdict.values())

    scapy.wrpcap(pcap, packetlist)

    return (v4len, v6len)


  def has_candidates(self):
    """
    True iff at least one IPv4 node and at least one IPv6 node are active.
    """
    if self.active_nodes[0] and self.active_nodes[1]:
      return True
    return False

  def has_ip4_candidates(self):
    if self.active_nodes[0]:
      return True
    return False

  def has_ip6_candidates(self):
    if self.active_nodes[1]:
      return True
    return False


################################################################################

def get_ts_tcp_seq(trace_set_id_list):
  h = hashlib.md5()
  for ts_id in trace_set_id_list:
    h.update(ts_id.encode('utf-8'))
  return int(h.hexdigest()[:8], 16)

def get_tcp_seq(trace_set_id):
  return int(trace_set_id[:8], 16)

def get_all_active_nodes(trace_set_list):
  """
  -> ( { ip4: { portlist } }, { ip6: { portlist } }, { ip4: { trace_set_id } }, { ip6: { trace_set_id } } )

  To assign the timestamp results to all trace sets containing the same IP, the 3rd and 4th return value can be used.
  """
  v4nodes = {} # all ip4 mapping to ports available
  v6nodes = {} # all ip6 mapping to ports available
  v4tracesetmap = {}
  v6tracesetmap = {}

  for trace_set_id, trace_set in trace_set_list.items():
    for trace in trace_set.get_traces().values():
      for ip, portlist in trace.get_active_nodes()[0].items():
        if ip in v4nodes:
          v4nodes[ip].update(portlist)
        else:
          v4nodes[ip] = set(portlist)

        if ip in v4tracesetmap:
          v4tracesetmap[ip].update([trace_set_id])
        else:
          v4tracesetmap[ip] = set([trace_set_id])

      for ip, portlist in trace.get_active_nodes()[1].items():
        if ip in v6nodes:
          v6nodes[ip].update(portlist)
        else:
          v6nodes[ip] = set(portlist)

        if ip in v6tracesetmap:
          v6tracesetmap[ip].update([trace_set_id])
        else:
          v6tracesetmap[ip] = set([trace_set_id])

  return (v4nodes, v6nodes, v4tracesetmap, v6tracesetmap)


def total_number_active_nodes(trace_set_dict):
  nr_nodes4 = 0
  nr_nodes6 = 0
  for trace_set in trace_set_dict.values():
    nr4, nr6 = trace_set.get_number_of_active_nodes()
    nr_nodes4 = nr_nodes4 + nr4
    nr_nodes6 = nr_nodes6 + nr6

  return (nr_nodes4, nr_nodes6)


def write_trace_sets(base_dir, trace_set_dict):
  """
  Returns number of written trace sets

  base_dir          absolute directory path to write trace sets
  trace_set_dict    { traceset_id: trace_set }
  """
  counter = 0
  for ts_id, traceset in trace_set_dict.items():
    traceset.to_file(base_dir)
    counter = counter + 1
  return counter


def load_trace_sets(base_dir, silent_dir = '', v4bl_re = None, v6bl_re = None, iface = None):
  """
  Loads all trace sets from base_dir, ignores silent_dir in base_dir.
  Use blacklist regex and interface to pass through to the Trace objects.
  Returns { trace_set_id: trace_set }
  """
  ts_dirs = [ os.path.join(base_dir, name) for name in os.listdir(base_dir) if os.path.isdir(os.path.join(base_dir, name)) and name not in silent_dir ]

  trace_set_dict = {}

  for ts_dir in ts_dirs:
    tset = TraceSet()
    tset.from_file(ts_dir, v4bl_re = v4bl_re, v6bl_re = v6bl_re, iface = iface)
    id = tset.id()
    if id not in trace_set_dict:
      trace_set_dict[id] = tset
    else:
      log.error('TraceSet ID {0} already in dictionary!'.format(tset.id()))

  return trace_set_dict
