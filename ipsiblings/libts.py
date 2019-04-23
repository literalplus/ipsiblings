# libts.py
#
# (c) 2018 Marco Starke
#


"""
This module provides functions to retrieve remote timestamps.
"""

import os
import csv
import time
import errno
import queue # only exceptions
import select
import random
import ipaddress
import threading
import contextlib
import multiprocessing
import scapy.all as scapy

import libtools
import libconstants as const
import libtrace
import liblog
log = liblog.get_root_logger()



def load_candidate_pairs(candidate_file, ts_data_file = None, delimiter = ';', port_delimiter = ',', v4bl_re = None, v6bl_re = None, include_domain = False):
  """
  Parameters:
  candidate_file    file to parse candidates from
  ts_data_file      optional load timestamp data from this file [None]
  delimiter         optional [';']
  port_delimiter    optional [',']
  v4bl_re           regex object to test for blacklisted IPs [None]
  v6bl_re           regex object to test for blacklisted IPs [None]
  include_domain    optional [False]

  Returns (ports_available, ts_data_available, tcp_opts_available, candidate_pairs { (ip4, ip6): CandidatePair } )

  Header must be present to determine csv structure.
  Expected format (domain is optional in any way):
  => len(row) == 2 -> ipv4; ipv6
  => len(row) == 3 -> ipv4; ipv6; domain
  => len(row) == 4 -> ipv4; ipv4_ports; ipv6; ipv6_ports
  => len(row) == 5 -> ipv4; ipv4_ports; ipv6; ipv6_ports; domain

  Ports have their own delimiter!

  If ts_data_file is explicitly given, the timestamp data is loaded and assigned to the candidate pairs accordingliy.
  In case ts_data_file is None, the function will try to load from
  os.path.join(os.path.dirname(candidate_file), CANDIDATE_PAIRS_DATA_FILE_NAME) as the last alternative.

  Timestamp data file format:
  IP4
  portA,tcp_ts,recv_ts,tcp_ts,recv_ts, ...
  portB,tcp_ts,recv_ts,tcp_ts,recv_ts, ...

  IP4
  ...
  =
  IP6
  portA,tcp_ts,recv_ts,tcp_ts,recv_ts, ...
  portB,tcp_ts,recv_ts,tcp_ts,recv_ts, ...

  IP6
  ...
  """
  if delimiter == port_delimiter:
    raise ValueError('Item delimiter and Port delimiter must not be the same character!')

  tcpopts_available = False

  tcpopts_file = os.path.join(os.path.dirname(candidate_file), const.CANDIDATE_PAIRS_TCP_OPTS_FILE_NAME)
  if os.path.isfile(tcpopts_file):
    tcpopts_available = True

  tcp_options = {}

  if tcpopts_available:
    log.info('TCP options available, loading from [{0}]'.format(tcpopts_file))
    # row = [ip, opt1:val1, opt2:val2, opt3:val3.1:val3.2, opt4:val4]
    with open(tcpopts_file, mode = "r", newline = '') as csvfile:
      csvreader = csv.reader(csvfile, delimiter = port_delimiter) # use ',' here
      for row in csvreader:
        ip = row[0]
        tcp_options[ip] = []
        for opt in row[1:]:
          name, *vals = opt.strip().split(':')
          values = []
          for v in vals:
            if v == 'None':
              values.append(None)
            else:
              values.append(v)
          if values and libtools.is_iterable(values): # safety first
            tcp_options[ip].append((name, tuple(values) if len(values) > 1 else values[0]))
          else:
            tcp_options[ip].append((name, None))


  have_timestamp_data = False
  ts_data_filename = None

  if not ts_data_file:
    assumed_file_path = os.path.join(os.path.dirname(candidate_file), const.CANDIDATE_PAIRS_DATA_FILE_NAME)
    if os.path.isfile(assumed_file_path):
      ts_data_filename = assumed_file_path
      have_timestamp_data = True
  else:
    ts_data_filename = ts_data_file
    have_timestamp_data = True

  ts_data4 = {}
  ts_data6 = {}

  if have_timestamp_data:
    log.info('Timestamp data available, loading from [{0}]'.format(ts_data_filename))
    with open(ts_data_filename, mode = "r") as tsdatafile:
      reader = csv.reader(tsdatafile, delimiter = ',') # constant delimiter here

      data = ts_data4
      # 0: read IP, 1: read port and timestamps
      state = 0 # start with reading IP address
      current_ip = None

      for row in reader:
        if not row: # go on with next IP address
          state = 0
          continue

        if row[0].startswith('='): # switch to IPv6 timestamps
          data = ts_data6
          state = 0
          continue

        if state == 0:
          current_ip = row[0]
          data[current_ip] = {}
          state = 1
          continue

        if state == 1: # port, tcp_ts, recv_ts, tcp_ts, recv_ts, ...
          port = int(row[0])
          remote_ts = [ int(x) for x in row[1::2] ] # slice all odd (starts at index 1)
          received_ts = [ float(x) for x in row[2::2] ] # slice all even (starts at index 2)
          timestamps = zip(remote_ts, received_ts) # build tuples (tcp_ts, recv_ts)
          data[current_ip][port] = list(timestamps) # generator to list
          # stay in state 1 until empty row reached
          continue

  if not ts_data4 or not ts_data6:
    ts_data_available = False
  else:
    ts_data_available = True


  candidate_pairs = {}

  with open(candidate_file, newline = '', encoding = 'utf-8') as csvfile:
    csvreader = csv.reader(csvfile, delimiter = delimiter)

    # determine csv structure according to function description
    header = next(csvreader)
    row_length = len(header) if include_domain else len(header) - 1 # domain always on last position

    row_func = lambda row: str(row) # will never be used

    if row_length == 2:
      row_func = lambda row: (str(ipaddress.ip_address(row[0])), None, str(ipaddress.ip_address(row[1])), None, [])
      ports_available = False
    elif row_length == 3:
      row_func = lambda row: (str(ipaddress.ip_address(row[0])), None, str(ipaddress.ip_address(row[1])), None, row[2].split(port_delimiter) if len(row) == 3 else [])
      ports_available = False
    elif row_length == 4:
      row_func = lambda row: (str(ipaddress.ip_address(row[0])), [int(p) for p in row[1].split(port_delimiter)], str(ipaddress.ip_address(row[2])), [int(p) for p in row[3].split(port_delimiter)], [])
      ports_available = True
    elif row_length == 5:
      row_func = lambda row: (str(ipaddress.ip_address(row[0])), [int(p) for p in row[1].split(port_delimiter)], str(ipaddress.ip_address(row[2])), [int(p) for p in row[3].split(port_delimiter)], row[4].split(port_delimiter) if len(row) == 5 else [])
      ports_available = True
    else:
      raise ValueError('Illegal file structure! Header length: {0}'.format(row_length))

    for row in csvreader:
      ip4, ports4, ip6, ports6, domains = row_func(row)

      if v4bl_re and v6bl_re and v4bl_re.match(ip4) and v6bl_re.match(ip6):
        log.info('IPv4 and IPv6 blacklisted: {0} / {1}'.format(ip4, ip6))
        continue
      if v4bl_re and v4bl_re.match(ip4):
        log.info('IPv4 blacklisted: {0} / {1}'.format(ip4, ip6))
        continue
      if v6bl_re and v6bl_re.match(ip6):
        log.info('IPv6 blacklisted: {0} / {1}'.format(ip4, ip6))
        continue

      if tcpopts_available:
        tcp4_opts = tcp_options.get(ip4, None)
        tcp6_opts = tcp_options.get(ip6, None)
      else:
        tcp4_opts = None
        tcp6_opts = None

      if ts_data_available:
        ip4_ts = ts_data4.get(ip4, None)
        ip6_ts = ts_data6.get(ip6, None)
      else:
        ip4_ts = None
        ip6_ts = None
      # set(domain) should always produce correct results since row[x].split(y) always returns a list
      cp = CandidatePair(ip4, ip6, ports4 = ports4, ports6 = ports6, tcp4_opts = tcp4_opts, tcp6_opts = tcp6_opts, ip4_ts = ip4_ts, ip6_ts = ip6_ts, domains = domains)
      candidate_pairs[(ip4, ip6)] = cp

  return (ports_available, ts_data_available, tcpopts_available, candidate_pairs)


def write_candidate_pairs(candidate_pairs, base_directory, delimiter = ';', port_delimiter = ',', only_active_nodes = True, write_candidates = True, write_ts_data = True, write_tcp_opts_data = True, include_domain = True):
  """
  Writes candidate pairs to base_directory/CANDIDATE_PAIRS_FILE_NAME and timestamp data,
  if available and desired, to base_directory/CANDIDATE_PAIRS_DATA_FILE_NAME.

  Return (candidate_lines_written, data_lines_written)
  """
  if not candidate_pairs:
    log.warning('No candidate pairs to write!')
    return (0, 0)

  if delimiter == port_delimiter:
    raise ValueError('Row delimiter and Port delimiter must not be the same character!')

  dir_status = libtools.create_directories(base_directory)
  if dir_status == True:
    log.info('Successfully created base directory [{0}]'.format(base_directory))
  elif dir_status is None:
    pass # do not issue a warning if already existing at this point
  else:
    log.error('Error while creating base directory [{0}] - Aborting ...'.format(base_directory))
    return (0, 0)

  cp_line_counter = 0
  data_line_counter = 0

  if write_candidates:
    longest_row = 0 # determine which header to use (domain may not be available on first entries)
    row_list = []

    for cp in candidate_pairs.values():
      if only_active_nodes and not cp.is_active():
        continue

      item_list = []
      item_list.append(cp.ip4)
      if cp.ports4:
        item_list.append(port_delimiter.join([ str(p) for p in sorted(cp.ports4) ]))
      item_list.append(cp.ip6)
      if cp.ports6:
        item_list.append(port_delimiter.join([ str(p) for p in sorted(cp.ports6) ]))
      if include_domain and cp.get_domains():
        item_list.append(port_delimiter.join(cp.get_domains()))

      if len(item_list) > longest_row:
        longest_row = len(item_list)

      row_list.append(delimiter.join(item_list))

    if row_list:
      if longest_row == 2:
        header = 'ip4;ip6'
      elif longest_row == 3:
        header = 'ip4;ip6;domain'
      elif longest_row == 4:
        header = 'ip4;ip4ports;ip6;ip6ports'
      elif longest_row == 5:
        header = 'ip4;ip4ports;ip6;ip6ports;domains'
      else:
        raise ValueError('Row length must be between 2 and 5 (was: {0})!'.format(longest_row))

      filename = os.path.join(base_directory, const.CANDIDATE_PAIRS_FILE_NAME)

      with open(filename, mode = "w") as outfile:
        outfile.write('{0}\n'.format(header))

        for row in row_list:
          outfile.write('{0}\n'.format(row))
          cp_line_counter = cp_line_counter + 1

      log.info('Candidate pairs written: {0} [{1}]'.format(cp_line_counter, str(filename)))
    else:
      log.warning('No active CandidatePairs available to write!')
      if not write_ts_data and not write_tcp_opts_data: # only return if nothing else to do
        return (0, 0)

  if write_ts_data:
    filename = os.path.join(base_directory, const.CANDIDATE_PAIRS_DATA_FILE_NAME)

    write_cache4 = []
    write_cache6 = []

    for cp in candidate_pairs.values():
      ip4_ts, ip6_ts = cp.get_timestamps()

      if ip4_ts:
        write_cache4.append('{0}\n'.format(str(cp.ip4)))
        for port, timestamps in ip4_ts.items():
          write_cache4.append(str(port))
          write_cache4.append(port_delimiter) # use ',' here
          write_cache4.append(port_delimiter.join(str(ts) for ts_tuple in timestamps for ts in ts_tuple)) # join the list of tuples into one string
          write_cache4.append('\n')
          data_line_counter = data_line_counter + 1
        write_cache4.append('\n')

      if ip6_ts:
        write_cache6.append('{0}\n'.format(str(cp.ip6)))
        for port, timestamps in ip6_ts.items():
          write_cache6.append(str(port))
          write_cache6.append(port_delimiter)
          write_cache6.append(port_delimiter.join(str(ts) for ts_tuple in timestamps for ts in ts_tuple))
          write_cache6.append('\n')
          data_line_counter = data_line_counter + 1
        write_cache6.append('\n')

    if write_cache4 or write_cache6: # only write file if any timestamps available
      with open(filename, mode = "w") as outfile:
        for string in write_cache4:
          outfile.write(string)
        outfile.write('=\n\n')
        for string in write_cache6:
          outfile.write(string)

      log.info('Timestamp records for {0} open ports written to [{1}]'.format(data_line_counter, str(filename)))
    else:
      log.warning('Although requested, no timestamps to write!')

  if write_tcp_opts_data:
    filename = os.path.join(base_directory, const.CANDIDATE_PAIRS_TCP_OPTS_FILE_NAME)
    line_counter = 0
    with open(filename, mode = "w") as outfile:
      for cp in candidate_pairs.values():
        if not cp.tcp4_opts or not cp.tcp6_opts:
          continue

        outstring4 = [cp.ip4]
        for name, opt in cp.tcp4_opts:
          if libtools.is_iterable(opt):
            values = [name]
            for v in opt:
              values.append(str(v))
            outstring4.append(':'.join(values))
          else:
            outstring4.append('{0}:{1}'.format(name, opt))
        line_counter = line_counter + 1
        outfile.write('{0}\n'.format(','.join(outstring4))) # constant delimiter here

        outstring6 = [cp.ip6]
        for name, opt in cp.tcp6_opts:
          if libtools.is_iterable(opt):
            values = [name]
            for v in opt:
              values.append(str(v))
            outstring6.append(':'.join(values))
          else:
            outstring6.append('{0}:{1}'.format(name, opt))
        line_counter = line_counter + 1
        outfile.write('{0}\n'.format(','.join(outstring6))) # constant delimiter here

    if line_counter > 0:
      log.debug('Finished writing TCP options to [{0}]'.format(filename))
    else: # remove the file if nothing was written
      with contextlib.suppress(FileNotFoundError):
        os.remove(filename)

  return (cp_line_counter, data_line_counter)


################################################################################
################################################################################


class TracePair(object):
  def __init__(self, ip4, ip6, domain = None):
    """
    Holds IP and domain information.
    """
    self.ip4 = ip4
    self.ip6 = ip6
    self.domain = domain


################################################################################
################################################################################


class CandidatePair(object):

  def __init__(self, ip4, ip6, ports4 = None, ports6 = None, tcp4_opts = None, tcp6_opts = None, ip4_ts = None, ip6_ts = None, domains = set()):
    """
    CandidatePair objects are based on IP addresses which means they may have multiple domains assigned.
    For example, google uses very often 172.217.18.14 / 2a00:1450:4001:80b::200e but also companies acquired by google (e.g. zynamics.com)
    """
    self.ip4 = ip4
    self.ip6 = ip6
    self.ports4 = ports4 if ports4 else set()
    self.ports6 = ports6 if ports6 else set()
    self.tcp4_opts = tcp4_opts
    self.tcp6_opts = tcp6_opts
    self.ip4_ts = ip4_ts if ip4_ts else {} # { port: [ (remote_ts, received_ts) ] }
    self.ip6_ts = ip6_ts if ip6_ts else {}
    self.domains = domains if type(domains) is set else set(domains)

    if ports4 and ports6:
      self.is_responsive4 = True
      self.is_responsive6 = True
    elif ports4 and not ports6:
      self.is_responsive4 = True
      self.is_responsive6 = False
    elif not ports4 and ports6:
      self.is_responsive4 = False
      self.is_responsive6 = True
    else:
      self.is_responsive4 = False
      self.is_responsive6 = False


  def add_domain(self, domain):
    self.domains.add(domain)


  def add_ts_record(self, ip, port, remote_ts, received_ts, tcp_options, ipversion):
    if ipversion == const.IP_VERSION_4:
      tsdata = self.ip4_ts
      # if not self.tcp4_opts: # usually done with portscanning for candidates
      #   self.tcp4_opts = tcp_options
    else: # hopefully 6
      tsdata = self.ip6_ts
      # if not self.tcp6_opts: # usually done with portscanning for candidates
      #   self.tcp6_opts = tcp_options

    if port in tsdata:
      tsdata[port].append((remote_ts, received_ts))
    else:
      tsdata[port] = [(remote_ts, received_ts)]


  def assign_portscan_record(self, port, tcp_opts, ipversion):
    self.add_port(port, ipversion)
    self.set_tcp_options(tcp_opts, ipversion)


  def add_port(self, port, ipversion):
    if ipversion == const.IP_VERSION_4:
      self.ports4.add(port)
      self.is_responsive4 = True
    elif ipversion == const.IP_VERSION_6:
      self.ports6.add(port)
      self.is_responsive6 = True
    else:
      raise ValueError("IP version can only be 4 or 6!")

  def set_ports4(self, ports):
    if ports:
      self.is_responsive4 = True
    else:
      log.debug('Assigned ports empty for {0}'.format(self.ip4))
    self.ports4 = ports

  def set_ports6(self, ports):
    if ports:
      self.is_responsive6 = True
    else:
      log.debug('Assigned ports empty for {0}'.format(self.ip6))
    self.ports6 = ports


  def set_tcp_options(self, options, ipversion):
    if ipversion == const.IP_VERSION_4:
      if not self.tcp4_opts:
        self.tcp4_opts = options
    elif ipversion == const.IP_VERSION_6:
      if not self.tcp6_opts:
        self.tcp6_opts = options
    else:
      raise ValueError("IP version can only be 4 or 6!")

  def get_ips(self):
    return (self.ip4, self.ip6)

  def get_ports(self):
    return (self.ports4, self.ports6)

  def get_timestamps(self):
    return (self.ip4_ts, self.ip6_ts)

  def get_tcp_options(self):
    return (self.tcp4_opts, self.tcp6_opts)

  def get_domains(self):
    return self.domains

  def is_responsive(self):
    return self.is_responsive4 and self.is_responsive6

  def is_active(self):
    return self.is_responsive()


################################################################################
################################################################################

class TSPortScan(object):
  """
  Base class - TraceSetPortScan / CandidatePortScan

  Override process_record function.
  """

  def __init__(self, nodes4, nodes6, *args, port_list = [x for x in range(const.PORT_MAX)], iface = 'en0', dump_unknown_packets = False, **kwargs):
    """
    Query port_list ports of nodes4 and nodes6.
    nodes4      iterable(ip4)
    nodes6      iterable(ip6)
    port_list   list of ports to test for TCP timestamp responses
    iface       interface to use
    dump_unknown_packets    dump packets which do not hold any timestamp information but have been captured
    """
    self.nodes4 = nodes4
    self.nodes6 = nodes6
    self.nodes4_length = len(nodes4)
    self.nodes6_length = len(nodes6)
    self.portlist = port_list
    self.portlist_length = len(port_list)
    self.iface = iface
    self.nr_v4packets = self.portlist_length * self.nodes4_length
    self.nr_v6packets = self.portlist_length * self.nodes6_length

    self.dump_packets = dump_unknown_packets
    self.dumped_packets = []

    self.sniff_proc = None
    self.stop_packet_load = 'STOP_{0}'.format(random.getrandbits(64))
    self.sending_processes = []

    self.mp_manager = multiprocessing.Manager()
    self.response_queue = self.mp_manager.Queue()
    self.v4sending_finished = self.mp_manager.Value('B', 0) # unsigned char
    self.v6sending_finished = self.mp_manager.Value('B', 0)
    self.total_records = self.mp_manager.Value('I', 0) # unsigned int

    self.packet_filter = 'tcp and (dst port {0} or dst port {1} or dst port {2})'.format(const.STOP_PORT, const.V4_PORT, const.V6_PORT)

    self.v4pkt = scapy.Ether()/scapy.IP()/scapy.TCP(sport = const.V4_PORT, flags = 'S', options = [('Timestamp', (const.TS_INITIAL_VAL, 0)), ('WScale', 0)]) # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)
    self.v6pkt = scapy.Ether()/scapy.IPv6()/scapy.TCP(sport = const.V6_PORT, flags = 'S', options = [('Timestamp', (const.TS_INITIAL_VAL, 0)), ('WScale', 0)]) # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)


  def process_record(self, record, *args, **kwargs):
    raise NotImplementedError()


  def _send4(self):
    socket4 = scapy.conf.L2socket(iface = self.iface)
    pkt = self.v4pkt.copy()
    for port in random.sample(self.portlist, k = self.portlist_length):
      pkt.payload.payload.dport = port
      for ip in random.sample(self.nodes4, k = self.nodes4_length):
        pkt.payload.dst = ip
        socket4.send(pkt)
    socket4.close()
    log.debug('Sending IPv4 packets finished, sent {0} packets'.format(self.nr_v4packets))
    self.v4sending_finished.value = 1

  def _send6(self):
    socket6 = scapy.conf.L2socket(iface = self.iface)
    pkt = self.v6pkt.copy()
    for port in random.sample(self.portlist, k = self.portlist_length):
      pkt.payload.payload.dport = port
      for ip in random.sample(self.nodes6, k = self.nodes6_length):
        pkt.payload.dst = ip
        socket6.send(pkt)
    socket6.close()
    log.debug('Sending IPv6 packets finished, sent {0} packets'.format(self.nr_v6packets))
    self.v6sending_finished.value = 1


  def _sniff(self):
    # https://github.com/secdev/scapy/issues/989 - own sniff implementation
    sock = scapy.conf.L2listen(iface = self.iface, type = scapy.ETH_P_ALL, filter = self.packet_filter)

    while True:
      try: # prevent sniff process to terminate on error (excludes KeyboardInterrupt and SystemExit)
        rlist = select.select([sock], [], [])
        if rlist:
          p = sock.recv() # returns exactly one packet -> socket.AF_PACKET
          if p[scapy.TCP].dport == const.STOP_PORT: # STOP packet handling
            if scapy.Raw in p and p[scapy.Raw].load.decode('utf-8') == self.stop_packet_load:
              # only break if we received the stop packet which matches the current instance
              log.debug('Received STOP packet [{0}] ...'.format(self.stop_packet_load))
              break
          ts = libtools.get_ts(p) # only packets with timestamp option set
          if ts:
            record = (p, ts)
            self.response_queue.put(record)
          else:
            if self.dump_packets:
              self.dumped_packets.append(p)
      except Exception as e:
        log.warning('[Ignored] Sniff Exception: {0} - {1}'.format(type(e).__name__, e))
        continue

    log.debug('Stopping sniff process ...')
    sock.close()


  def _stop_sniff(self):
    # send STOP packet to localhost - to be sure do this for IPv4 and IPv6
    p4 = scapy.Ether()/scapy.IP(dst = '127.0.0.1')/scapy.TCP(dport = const.STOP_PORT)/scapy.Raw(load = self.stop_packet_load)
    p6 = scapy.Ether()/scapy.IPv6(dst = '::1')/scapy.TCP(dport = const.STOP_PORT)/scapy.Raw(load = self.stop_packet_load)
    scapy.sendp([p4, p6], verbose = 0)


  def start(self):
    """
    Start timestamp port query for given IPs.
    """
    self.sniff_proc = multiprocessing.Process(name = 'sniff', target = self._sniff)
    v4proc = multiprocessing.Process(name = 'v4send', target = self._send4)
    v6proc = multiprocessing.Process(name = 'v6send', target = self._send6)

    self.sending_processes.extend([v4proc, v6proc])

    self.sniff_proc.start()
    self.sniff_proc.join(const.START_SNIFF_PROCESS_DELAY)

    v4proc.start()
    v6proc.start()

    log.debug('Started timestamp port identification process ...')
    log.debug('IPv4 / IPv6 packets to send: {0} / {1}'.format(self.nr_v4packets, self.nr_v6packets))

    return self


  def is_running(self):
    """
    Returns True if and only if one of the sending processes is alive.
    """
    return any(p.is_alive() for p in self.sending_processes)


  def wait(self, timeout = 1):
    """
    Joins the sniffing process for timeout seconds.
    If timeout is None, wait returns after 1 second.
    """
    if not timeout:
      timeout = 1
    if self.sniff_proc.is_alive():
      self.sniff_proc.join(timeout)


  def stop(self):
    for p in self.sending_processes:
      if p.is_alive():
        p.terminate()
      # else: # requires Python >= 3.7
      #   p.close()
    self._stop_sniff()


  def finished(self):
    """
    Returns True if and only if IPv4 and IPv6 sending processes finished their task.
    """
    return bool(self.v4sending_finished.value * self.v6sending_finished.value)


  def process_results(self, *args, timeout = 1, **kwargs):
    if not timeout:
      timeout = 1

    nr_records = 0

    while True:
      try:
        record = self.response_queue.get(timeout = timeout)
        if self.process_record(record, *args, **kwargs):
          nr_records = nr_records + 1
      except queue.Empty:
        if nr_records > 0:
          log.debug('Current number of records processed: {0}'.format(nr_records))
          self.total_records.value = self.total_records.value + nr_records
        else:
          log.debug('No records processed')
        break
      except Exception as e:
        log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
        break


  def get_total_records_processed(self):
    return self.total_records.value


################################################################################
################################################################################

class TraceSetPortScan(TSPortScan):

  def __init__(self, nodes4, nodes6, port_list = [x for x in range(const.PORT_MAX)], iface = 'en0'):
    super().__init__(nodes4, nodes6, port_list = port_list, iface = iface)
    self.v4results, self.v6results = {}, {}

  def process_record(self, record):
    # { IP: { port: (remote_ts, received_ts, packet) } }
    p, ts = record
    ipversion = p.payload.version
    ip = p.payload.src
    port = p.payload.payload.sport
    remote_ts = ts[0]
    received_ts = int(p.time)

    if ipversion == const.IP4:
      if ip in self.v4results:
        if port in self.v4results[ip]:
          self.v4results[ip][port].append((remote_ts, received_ts, p))
        else:
          self.v4results[ip][port] = [(remote_ts, received_ts, p)]
      else:
        self.v4results[ip] = { port: [(remote_ts, received_ts, p)] }
    elif ipversion == const.IP6:
      if ip in self.v6results:
        if port in self.v6results[ip]:
          self.v6results[ip][port].append((remote_ts, received_ts, p))
        else:
          self.v6results[ip][port] = [(remote_ts, received_ts, p)]
      else:
        self.v6results[ip] = { port: [(remote_ts, received_ts, p)] }
    else:
      return False # should never reach here

    return True


  def results(self):
    return (self.v4results, self.v6results)


################################################################################
################################################################################

class CandidatePortScan(TSPortScan):

  def process_record(self, record, ip_cp_lut):
    if not ip_cp_lut:
      log.warning('CandidatePortScan: Invalid data structure for output submitted!')
      return False
    try:
      p, ts = record
      ip = p.payload.src
      port = p.payload.payload.sport
      tcp_options = p.payload.payload.options
      ipversion = p.payload.version

      for cp in ip_cp_lut[ip]:
        cp.assign_portscan_record(port, tcp_options, ipversion)
    except Exception as e:
      log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
      return False

    return True


################################################################################
################################################################################

class Harvester(object):
  """
  Base class - TraceSetHarvester / CandidateHarvester

  Override __init__ and process_record functions.
  """

  def __init__(self, *args, runtime = 360, interval = 10, iface = 'en0', **kwargs):
    """
    Base class __init__ must be called in sub class before constructing packets to send!

    data_structure    { ID: Object } - Holds an object which manages
                      all available candidates/trace sets (part of *args).
    runtime           runtime in seconds
    interval          interval of timestamp collection runs
    iface             interface to use

    Usage example:

    harvester = libts.[SubClass]Harvester(dstruct, runtime = 5, interval = 1, iface = nic)
    harvester.start()
    while not harvester.finished():
      harvester.process_results(timeout = 1)
    harvester.process_results(timeout = 2)

    After the return of the last call to process_results, the data structure objects are
    filled with the corresponding responses.
    Raises ValueError if data structure is empty or None
    """
    self.runtime = runtime
    self.interval = interval
    self.iface = iface

    self.run_thread = None

    self.mp_manager = multiprocessing.Manager()

    self.runs_stop_event = self.mp_manager.Event()
    self.runs_stop_event.clear()
    self.stop_packet_load = 'STOP_{0}'.format(random.getrandbits(64))

    self.response_queue = self.mp_manager.Queue()

    # typecodes - https://docs.python.org/3.7/library/array.html
    self.stop_all = self.mp_manager.Value('B', 0) # unsigned char
    self.runs_completed = self.mp_manager.Value('B', 0)

    self.nr_runs = self.mp_manager.Value('I', int(runtime / interval)) # unsigned int
    self.run_counter = self.mp_manager.Value('I', 1)
    self.total_records = self.mp_manager.Value('I', 0)

    self.packet_filter = '((tcp) and ((dst port {0}) or (dst port {1}) or (dst port {2})))'.format(const.V4_PORT, const.V6_PORT, const.STOP_PORT)

    self.v4pkt = scapy.Ether()/scapy.IP()/scapy.TCP(sport = const.V4_PORT, flags = 'S', options = [('Timestamp', (const.TS_INITIAL_VAL, 0)), ('WScale', 0)]) # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)
    self.v6pkt = scapy.Ether()/scapy.IPv6()/scapy.TCP(sport = const.V6_PORT, flags = 'S', options = [('Timestamp', (const.TS_INITIAL_VAL, 0)), ('WScale', 0)]) # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)

    # since each process only reads one variable, it should be sufficient to use simple lists
    self.v4packets = []
    self.v6packets = []


  def process_record(self, record, *args, **kwargs):
    """
    Handles the assignment of records received to the corresponding objects.
    """
    raise NotImplementedError()



  def _send4(self):
    socket4 = scapy.conf.L2socket(iface = self.iface)
    for pkt in random.sample(self.v4packets, k = self.v4packets_length):
      if self.stop_all.value == 1:
        log.debug('Stopping IPv4 sending process ...')
        break
      socket4.send(pkt)
    socket4.close()

  def _send6(self):
    socket6 = scapy.conf.L2socket(iface = self.iface)
    for pkt in random.sample(self.v6packets, k = self.v6packets_length):
      if self.stop_all.value == 1:
        log.debug('Stopping IPv6 sending process ...')
        break
      socket6.send(pkt)
    socket6.close()


  def _sniff(self):
    # https://github.com/secdev/scapy/issues/989 - own sniff implementation

    sock = scapy.conf.L2listen(filter = self.packet_filter)

    while True:
      try: # prevent sniff process to terminate on error (excludes KeyboardInterrupt and SystemExit)
        rlist = select.select([sock], [], [])
        if rlist:
          p = sock.recv()
          # STOP packet handling
          if p[scapy.TCP].dport == const.STOP_PORT:
            if scapy.Raw in p and p[scapy.Raw].load.decode('utf-8') == self.stop_packet_load:
              # only break if we received the stop packet which matches the current instance
              log.debug('Received STOP packet [{0}] ...'.format(self.stop_packet_load))
              break
          ts_tuple = libtools.get_ts(p) # (TSval, TSecr)
          if ts_tuple:
            remote_ts = ts_tuple[0] # TSval
          else:
            continue # if no timestamp available ignore packet

          # (tcp_seq, node_ip, remote_port, remote_ts, received_ts, tcp_options, ip_version)
          record = (p.payload.payload.ack - 1, p.payload.src, p.payload.payload.sport, remote_ts, p.time, p[scapy.TCP].options, p.payload.version)
          # local timestamps are provided as e.g. 1541763777.398191 (microseconds)
          # remote timestamps in seconds only

          self.response_queue.put(record)

        if self.stop_all.value == 1:
          break
      except Exception as e:
        log.warning('[Ignored] Sniff Exception: {0} - {1}'.format(type(e).__name__, e))
        continue

    log.debug('Stopping sniff process ...')

    sock.close()


  def _run(self):

    self.send4 = multiprocessing.Process(target = self._send4, name = '({0}) send4'.format(self.run_counter.value))
    self.send6 = multiprocessing.Process(target = self._send6, name = '({0}) send6'.format(self.run_counter.value))

    self.send4.start()
    self.send6.start()


  def _start(self):
    """
    Repeat the _run function call at each interval until the runs_stop_event is set or the requested number of runs is reached
    """
    while True:
      log.info('Started run {0}'.format(self.run_counter.value))

      self.run_thread = threading.Thread(target = self._run)
      self.run_thread.start()

      if self.run_counter.value >= self.nr_runs.value:
        self.run_thread.join(1) # give the run_thread some time to create the sending processes
        # block until BOTH sending processes finish their current run
        self.send4.join()
        self.send6.join()
        self.runs_completed.value = 1
        break

      self.run_counter.value = self.run_counter.value + 1

      # control the timing
      # blocks until interval passed (return False) or event is set (return True)
      if self.runs_stop_event.wait(timeout = self.interval):
        break


  def start(self):
    """
    Returns the thread handle for the control thread which calls the _run function each defined interval.
    Starts the sniffing process.
    """
    self.sniff_proc = multiprocessing.Process(target = self._sniff, name = 'sniff')
    self.sniff_proc.start()
    # allow enough time to setup sniffing process
    self.sniff_proc.join(const.START_SNIFF_PROCESS_DELAY)

    t = threading.Thread(target = self._start)
    t.start()
    return t


  def _stop_sniff(self):
    # send STOP packet to localhost - to be sure do this for IPv4 and IPv6
    p4 = scapy.Ether()/scapy.IP(dst = '127.0.0.1')/scapy.TCP(dport = const.STOP_PORT)/scapy.Raw(load = self.stop_packet_load)
    p6 = scapy.Ether()/scapy.IPv6(dst = '::1')/scapy.TCP(dport = const.STOP_PORT)/scapy.Raw(load = self.stop_packet_load)
    scapy.sendp(p4, verbose = 0)
    scapy.sendp(p6, verbose = 0)


  def stop(self):
    log.debug('Stop requested ...')
    self.stop_all.value = 1
    self.runs_stop_event.set()

    self._stop_sniff()

    if self.runs_completed.value != 1: # only necessary if runs are not already completed
      if self.run_thread:
        log.debug('Waiting for _run thread to finish (this may take some time depending on number of packets to process) ...')
        self.run_thread.join()
      else:
        log.debug('No _run thread to join ...')


  def finished(self):
    """
    True if and only if all runs and sending processes have finished.
    Waiting for responses is up to the caller.
    """
    return bool(self.runs_completed.value)


  def wait(self, timeout):
    """
    Wait for a given timeout.
    Timeout must be a positive number otherwise this will cause a life lock.
    To prevent unresponsive behaviour timeout is set to 1 second if input was faulty.
    Joins the sniff process.
    """
    if timeout and timeout > 0:
      self.sniff_proc.join(timeout)
    else:
      self.sniff_proc.join(1)


  def total_records_processed(self):
    return self.total_records.value


  def process_results(self, timeout):
    """
    Queries the response_queue for records and writes them to the corresponding TraceSet object.
    Waits 'timeout' seconds for data, if no data is available return.
    Returns the number of currently processed records
    If harvesting has finished and this is the last call for result assignment,
    the function blocks for 'timeout' seconds and performs as usual after this waiting period.
    During the last call, it also stops the sniffing process which means no further
    calls to functions which control the processes are necessary.

    Keep in mind that if the timeout parameter is >= the sending interval, the function
    will (probably) never return since there will always be new data available within the given timeout ...
    """
    # If this is the last call, wait for late responses.
    # This leaves some space for a race condition if sending finishes after the
    # function entry while running the caller's while loop -> getting scheduled immediately
    # after entering the function and during this time sending may be finished ...
    if self.runs_completed.value == 1 and self.sniff_proc.is_alive():
      log.info('Runs completed, waiting for final responses ...')
      self.sniff_proc.join(timeout)
      finished_before_call = True
    else:
      finished_before_call = False

    nr_records = 0

    while True:
      try:
        record = self.response_queue.get(timeout = timeout)
        # (tcp_seq, node_ip, remote_port, remote_ts, received_ts, tcp_options, ip_version)

        self.process_record(record)

        nr_records = nr_records + 1
      except queue.Empty:
        if nr_records > 0:
          log.debug('Current number of records processed: {0}'.format(nr_records))
          self.total_records.value = self.total_records.value + nr_records
        else:
          if not finished_before_call:
            log.debug('No records processed')
        break
      except Exception as e:
        log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
        break

    if finished_before_call:
      self._stop_sniff()

    return nr_records


################################################################################
################################################################################

class TraceSetHarvester(Harvester):
  """
  Collect timestamps to fill trace data of trace sets.
  """

  def __init__(self, trace_set_dict, runtime = 360, interval = 10, iface = 'en0'):
    if not trace_set_dict:
      raise ValueError('TraceSet dictionary is empty!')


    super().__init__(runtime = runtime, interval = interval, iface = iface)


    self.trace_set_dict = trace_set_dict

    # ( { ip4: { portlist } }, { ip6: { portlist } }, { ip4: { trace_set_id } }, { ip6: { trace_set_id } } )
    active_nodes4, active_nodes6, ip4_tracesets_lut, ip6_tracesets_lut = libtrace.get_all_active_nodes(self.trace_set_dict)
    self.ip_tracesets_lut = { **ip4_tracesets_lut, **ip6_tracesets_lut }

    # prepare packets to send in each run
    for ip4, portlist in active_nodes4.items():
      tcp_seq = libtrace.get_ts_tcp_seq(ip4_tracesets_lut[ip4])
      p = self.v4pkt.copy()
      p.payload.dst = ip4
      p.payload.payload.seq = tcp_seq
      for port in portlist:
        pkt = p.copy()
        pkt.payload.payload.dport = int(port)
        self.v4packets.append(pkt)

    for ip6, portlist in active_nodes6.items():
      tcp_seq = libtrace.get_ts_tcp_seq(ip6_tracesets_lut[ip6])
      p = self.v6pkt.copy()
      p.payload.dst = ip6
      p.payload.payload.seq = tcp_seq
      for port in portlist:
        pkt = p.copy()
        pkt.payload.payload.dport = int(port)
        self.v6packets.append(pkt)

    self.v4packets_length = len(self.v4packets)
    self.v6packets_length = len(self.v6packets)

    log.info('Constructed packets to be sent each run: {0} v4 packets / {1} v6 packets / {2} combined'.format(self.v4packets_length, self.v6packets_length, self.v4packets_length + self.v6packets_length))


  def process_record(self, record):
    tcp_seq, ip, port, remote_ts, received_ts, tcp_options, ipversion = record

    trace_set_ids = self.ip_tracesets_lut[ip]
    for ts_id in trace_set_ids:
      self.trace_set_dict[ts_id].add_record(ip, port, (remote_ts, received_ts), tcp_options, ipversion)


################################################################################
################################################################################

class CandidateHarvester(Harvester):

  def __init__(self, candidate_pairs, runtime = 360, interval = 10, iface = 'en0'):
    if not candidate_pairs:
      raise ValueError('Candidate pairs empty!')


    super().__init__(runtime = runtime, interval = interval, iface = iface)


    self.candidate_pairs = candidate_pairs

    self.cp_lut = {}

    for cp in self.candidate_pairs.values():
      if not cp.is_responsive():
        continue

      if cp.ip4 not in self.cp_lut:
        self.cp_lut[cp.ip4] = cp
      if cp.ip6 not in self.cp_lut:
        self.cp_lut[cp.ip6] = cp

      p4 = self.v4pkt.copy()
      p6 = self.v6pkt.copy()
      p4.payload.dst = cp.ip4
      p6.payload.dst = cp.ip6
      for port in cp.ports4:
        pkt = p4.copy()
        pkt.payload.payload.dport = int(port)
        self.v4packets.append(pkt)
      for port in cp.ports6:
        pkt = p6.copy()
        pkt.payload.payload.dport = int(port)
        self.v6packets.append(pkt)

    self.v4packets_length = len(self.v4packets)
    self.v6packets_length = len(self.v6packets)

    log.info('Constructed packets to be sent each run: {0} v4 packets / {1} v6 packets / {2} combined'.format(self.v4packets_length, self.v6packets_length, self.v4packets_length + self.v6packets_length))


  def process_record(self, record):
    tcp_seq, ip, port, remote_ts, received_ts, tcp_options, ipversion = record

    cp = self.cp_lut[ip]
    cp.add_ts_record(ip, port, remote_ts, received_ts, tcp_options, ipversion)
