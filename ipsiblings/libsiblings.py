# libsiblings.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

import os
import csv
import numpy
import pandas
import itertools
import collections
import matplotlib # rc_context -> {'interactive': False }
import matplotlib.pyplot as plt
import matplotlib.backends.backend_pdf # PdfPages
from scipy import stats
from scipy import interpolate

import libconstants as const
import liblog
log = liblog.get_root_logger()



def construct_node_candidates(candidate_pairs, all_ports_timestamps = False, low_runtime = False, nr_timestamps = None):
  """
  Constructs a dictionary structured as shown below.
  Per default, the lowest common port (if multiple ports are available) is used to construct the
  sibling candidate. In case of no ports in common, the lowest of each IP is used.

  all_ports_timestamps    construct candidates for each port combination (cartesian product) [default: False]
  low_runtime             use LowRTSiblingCandidate class

  Returns:
  -> { ip4_port4_ip6_port6: SiblingCandidate }
  """
  if not candidate_pairs:
    return {}

  candidates = {}

  if not any([ cp.is_responsive() for cp in candidate_pairs.values() ]):
    log.warning('No timestamp data available! Candidate pairs need harvesting first!')
    return candidates

  for cp in candidate_pairs.values():
    if not cp.is_responsive():
      continue

    if all_ports_timestamps:
      if nr_timestamps:
        scs = from_CandidatePair(cp, all_ports = True, low_runtime = True, nr_timestamps = nr_timestamps)
      else:
        scs = from_CandidatePair(cp, all_ports = True, low_runtime = low_runtime)
      candidates = { **candidates, **scs }
    else:
      if nr_timestamps:
        key, sc = from_CandidatePair(cp, all_ports = False, low_runtime = True, nr_timestamps = nr_timestamps)
      else:
        key, sc = from_CandidatePair(cp, all_ports = False, low_runtime = low_runtime)

      if not key or not sc: # faulty candidate pair provided
        continue
      candidates[key] = sc

  return candidates


def construct_trace_candidates(trace_sets, all_ports_timestamps = False, low_runtime = False, add_traces = False):
  """
  Constructs a dictionary structured as shown below.
  Uses the port index which offers the most timestamps.

  all_ports_timestamps    construct candidates for each port combination (cartesian product) [default: False]
  low_runtime             use LowRTSiblingCandidate class

  Returns:
  -> { ip4_port4_ip6_port6: SiblingCandidate }
  """
  if not trace_sets:
    return {}

  candidates = {}

  # check if any trace set has timestamp data available
  if not any([ ts.has_timestamp_data() for ts in trace_sets.values() ]):
    log.warning('No timestamp data available! Trace sets need harvesting first!')
    return candidates

  for trace_set in trace_sets.values():
    if not trace_set.has_timestamp_data():
      continue

    v4nodes, v6nodes = trace_set.get_active_nodes()
    candidates_ips = itertools.product(v4nodes.keys(), v6nodes.keys()) # [ (ip4, ip6) ]
    td4 = trace_set.get_trace_data()[4] # { ip: { port: [ (remote_ts, received_ts) ] } }
    td6 = trace_set.get_trace_data()[6]
    tcp_options = trace_set.get_tcp_options()
    trace_set_id = trace_set.id()

    if add_traces:
      trace_data = ([ trace.get_trace_lists() for trace in trace_set.get_traces().values() ], trace_set.get_target())
    else:
      trace_data = None

    # for each responding node in this trace set
    for cand_ip4, cand_ip6 in candidates_ips:
      # tcp options
      if tcp_options:
        opt4 = tcp_options.get(cand_ip4)
        opt6 = tcp_options.get(cand_ip6)
      else:
        opt4, opt6 = None, None
      # timestamps
      port_ts4 = td4.get(cand_ip4)
      port_ts6 = td6.get(cand_ip6)

      if not port_ts4 or not port_ts6: # if no timestamps available for this ip continue
        log.info('[{0}] {1} / {2} - Not enough timestamp data available ... skipping ...'.format(trace_set_id, cand_ip4, cand_ip6))
        continue

      ports4 = list(port_ts4.keys())
      ports6 = list(port_ts6.keys())
      has_ssh = const.SSH_PORT in ports4 and const.SSH_PORT in ports6

      if all_ports_timestamps:
        ports = itertools.product(ports4, ports6)
        # for each responding port of the current IPs
        for port4, port6 in ports:
          key = '{0}_{1}_{2}_{3}'.format(cand_ip4, port4, cand_ip6, port6)
          if key in candidates: # no need to recreate SiblingCnadidate object
            continue

          if low_runtime:
            siblingcandidate = LowRTSiblingCandidate(cand_ip4, cand_ip6, port4, port6, port_ts4[port4], port_ts6[port6], opt4, opt6, ssh_available = has_ssh, trace_set_id = trace_set_id, trace_data = trace_data)
          else:
            siblingcandidate = SiblingCandidate(cand_ip4, cand_ip6, port4, port6, port_ts4[port4], port_ts6[port6], opt4, opt6, ssh_available = has_ssh, trace_set_id = trace_set_id, trace_data = trace_data)
          candidates[key] = siblingcandidate

      else:
        # use port which delivers the maximum number of timestamps
        port_index4, timestamps4 = max(port_ts4.items(), key = lambda x: len(x[1]))
        port_index6, timestamps6 = max(port_ts6.items(), key = lambda x: len(x[1]))
        # default branch -> use the lowest common port or the lowest of v4/v6 timestamps
        # intersecting_ports = set(port_ts4.keys()).intersection(set(port_ts6.keys()))
        # if not intersecting_ports: # no common ports
        #   # choose the lowest port
        #   port_index4, port_index6 = sorted(port_ts4.keys())[0], sorted(port_ts6.keys())[0]
        #   timestamps4, timestamps6 = port_ts4[port_index4], port_ts6[port_index6]
        # else:
        #   port_index = sorted(intersecting_ports)[0] # take the lowest port in common
        #   timestamps4, timestamps6 = port_ts4[port_index], port_ts6[port_index]
        #   port_index4 = port_index6 = port_index

        key = '{0}_{1}_{2}_{3}'.format(cand_ip4, port_index4, cand_ip6, port_index6)
        if key in candidates: # no need to recreate SiblingCnadidate object
          continue

        if low_runtime:
          siblingcandidate = LowRTSiblingCandidate(cand_ip4, cand_ip6, port_index4, port_index6, timestamps4, timestamps6, opt4, opt6, ssh_available = has_ssh, trace_set_id = trace_set_id, trace_data = trace_data)
        else:
          siblingcandidate = SiblingCandidate(cand_ip4, cand_ip6, port_index4, port_index6, timestamps4, timestamps6, opt4, opt6, ssh_available = has_ssh, trace_set_id = trace_set_id, trace_data = trace_data)
        candidates[key] = siblingcandidate

  return candidates


################################################################################
################################################################################

def from_CandidatePair(cp, all_ports = False, low_runtime = False, nr_timestamps = None):
  """
  Returns a SiblingCandidate object or a list of such if all_ports is True.
  key = ip4_port4_ip6_port6
  -> (key, SiblingCandidate) or { key: SiblingCandidate }
  """
  ip4, ip6 = cp.get_ips()
  ts4, ts6 = cp.get_timestamps()

  # ports4, ports6 = cp.get_ports()
  # not for all ports are probably timestamps available
  # cp.get_ports() != (ts4.keys(), ts6.keys())
  # -> to be sure use the dict keys of the timestamp data
  ports4, ports6 = list(ts4.keys()), list(ts6.keys())
  # based on this experience, we must check if there is timestamp data available at all
  invalid_candidate = False
  if len(ports4) < 1:
    # log.warning('[{0}] / {1} ({2} - {3}) - No timestamp data available!'.format(ip4, ip6, getattr(cp, 'domains', 'None'), cp.get_ports()))
    invalid_candidate = True

  if len(ports6) < 1:
    # log.warning('{0} / [{1}] ({2} - {3}) - No timestamp data available!'.format(ip4, ip6, getattr(cp, 'domains', 'None'), cp.get_ports()))
    invalid_candidate = True

  if invalid_candidate: # if there is no data available we must ignore this candidate
    if all_ports:
      return {}
    else:
      return (None, None)

  opts4, opts6 = cp.get_tcp_options()
  domains = cp.get_domains()

  has_ssh = const.SSH_PORT in ports4 and const.SSH_PORT in ports6

  if all_ports:
    candidates = {}
    ports = itertools.product(ports4, ports6)
    for p4, p6 in ports:
      key = '{0}_{1}_{2}_{3}'.format(ip4, p4, ip6, p6)
      if low_runtime:
        sc = LowRTSiblingCandidate(ip4, ip6, p4, p6, ts4[p4], ts6[p6], opts4, opts6, domains = domains, ssh_available = has_ssh, nr_timestamps = nr_timestamps)
      else:
        sc = SiblingCandidate(ip4, ip6, p4, p6, ts4[p4], ts6[p6], opts4, opts6, domains = domains, ssh_available = has_ssh)
      candidates[key] = sc

    return candidates

  else:
    # use port which delivers the maximum number of timestamps
    p4, timestamps4 = max(ts4.items(), key = lambda x: len(x[1]))
    p6, timestamps6 = max(ts6.items(), key = lambda x: len(x[1]))
    # intersecting_ports = set(ports4).intersection(set(ports6))
    # if not intersecting_ports:
    #   p4, p6 = sorted(ports4)[0], sorted(ports6)[0]
    #   timestamps4, timestamps6 = ts4[p4], ts6[p6]
    # else:
    #   common_port = sorted(intersecting_ports)[0]
    #   timestamps4, timestamps6 = ts4[common_port], ts6[common_port]
    #   p4, p6 = common_port, common_port

    key = '{0}_{1}_{2}_{3}'.format(ip4, p4, ip6, p6)
    if low_runtime:
      sc = LowRTSiblingCandidate(ip4, ip6, p4, p6, timestamps4, timestamps6, opts4, opts6, domains = domains, ssh_available = has_ssh, nr_timestamps = nr_timestamps)
    else:
      sc = SiblingCandidate(ip4, ip6, p4, p6, timestamps4, timestamps6, opts4, opts6, domains = domains, ssh_available = has_ssh)

    return (key, sc)

################################################################################
################################################################################


def plot_all(candidates, fname, func = None, funckwargs = {}):
  """
  Plots all given SiblingCandidate objects.
  """
  with matplotlib.rc_context(rc = { 'interactive': False }):
    plotfile = os.path.abspath(os.path.join(const.BASE_DIRECTORY, fname))

    if func:
      pp = None
      plotfunc = func
      args = funckwargs
    else:
      pp = matplotlib.backends.backend_pdf.PdfPages(plotfile)
      def pfunc(fig, pdf = None):
        if pdf:
          pdf.savefig(fig)
      plotfunc = pfunc
      args = { 'pdf': pp }

    counter = 0
    for s in candidates:
      # fname = None, func = None, funckwargs = None, title = None, titlefontsize = 10, xticks = None, xlabel = None, ylabel = None, legend = None):
      if s.plot(func = plotfunc, funckwargs = args):
        counter = counter + 1

    if pp:
      pp.close()

  log.info('Plotted [{0}] candidates to file [{1}]'.format(counter, plotfile))

################################################################################
################################################################################

def prepare_tcp_opts(tcpopts, delimiter = '-'):
  if tcpopts:
    out = []
    for k, v in tcpopts: # list of tuples (name, value)
      if k == 'WScale':
        out.append('WS{0:0>2}'.format(v))
      elif k == 'Timestamp':
        out.append('TS')
      else:
        out.append(k)

    return delimiter.join(out)
  else:
    return ''

def prepare_domains(domains, delimiter = ','):
  if domains:
    return delimiter.join(domains)
  else:
    return ''

def write_results(candidates, resultfile, low_runtime = False, delimiter = ';'):
  """
  Write available results to resultfile
  """
  if low_runtime:
    keys = [ 'ip4', 'ip6', 'port4', 'port6', 'domains', 'hz4', 'hz6', 'hz4_R2', 'hz6_R2', 'raw_ts_diff', 'ip4_tcpopts', 'ip6_tcpopts', 'ssh_keys_match', 'ssh_agents_match', 'geo4', 'geo6', 'geoloc_diff', 'status', 'is_sibling' ]
  else:
    keys = [ 'ip4', 'ip6', 'port4', 'port6', 'domains', 'hz4', 'hz6', 'hz4_R2', 'hz6_R2', 'raw_ts_diff', 'alpha4', 'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'theta', 'dynrange4', 'dynrange6', 'dynrange_diff', 'dynrange_diff_rel', 'spl_percent_val', 'ip4_tcpopts', 'ip6_tcpopts', 'ssh_keys_match', 'ssh_agents_match', 'geo4', 'geo6', 'geoloc_diff', 'status', 'is_sibling' ]

  linecounter = 0
  with open(resultfile, mode = 'w', newline = '') as csvfile:
    csvout = csv.writer(csvfile, delimiter = delimiter)
    csvout.writerow(keys) # write header
    for candidate in candidates:
      res = candidate.get_results()
      line = []
      for key in keys:
        if key == 'domains':
          line.append(prepare_domains(res[key]))
        elif key == 'ip4_tcpopts' or key == 'ip6_tcpopts':
          line.append(prepare_tcp_opts(res[key]))
        else:
          line.append(res[key])

      csvout.writerow(line)
      linecounter = linecounter + 1

  return linecounter


################################################################################
################################################################################
################################################################################


class SiblingEvaluationError(Exception):
  def __init__(self, *args, sibling_status = None, **kwargs):
    super().__init__(*args, **kwargs)
    self.sibling_status = sibling_status

################################################################################
################################################################################

class SiblingCandidate(object):
  """
  Represents a concrete SiblingCandidate.
  """

  # TS_DIFF_THRESHOLD = 0.2557 # Scheitle et al.
  TS_DIFF_THRESHOLD = 0.305211037 # ours

  def __init__(self, ip4, ip6, port4, port6, ip4_ts, ip6_ts, ip4_tcpopts, ip6_tcpopts, domains = None, ssh_available = False, ssh_keys = None, trace_set_id = None, trace_data = None):
    self.sibling_status = const.SIB_STATUS_UNKNOWN
    self.calc_finished = False # flag to check if calculations have finished (due to error or valid result)
    self.is_sibling = False
    self.calc_error = False # flag to check if exception occurred -> correct status assignment

    self.ip4 = ip4
    self.ip6 = ip6
    self.port4 = port4
    self.port6 = port6
    self.domains = domains # may be None
    self.recv_offset4 = None
    self.recv_offset6 = None

    dt = numpy.dtype('int64, float64') # data type for numpy array
    columns = ['remote', 'received'] # column/index name -> e.g. access with ip4_ts['remote']
    dt.names = columns

    self.ip4_ts = numpy.array(ip4_ts, dtype = dt)
    self.ip6_ts = numpy.array(ip6_ts, dtype = dt)
    self.recv_offset4 = self.ip4_ts['received'][0] # timestamp data e.g. 1541886109.485699 (float)
    self.recv_offset6 = self.ip6_ts['received'][0]
    self.tcp_offset4 = self.ip4_ts['remote'][0] # timestamp data e.g. 1541886109 (uint32)
    self.tcp_offset6 = self.ip6_ts['remote'][0]

    self.ip4_tcpopts = ip4_tcpopts
    self.ip6_tcpopts = ip6_tcpopts
    self.tcp_opts_differ = self.calc_tcp_opts_differ() # if None, no tcp options are available -> ignore
    # if None, no geo information available; additionally, fills self.geodiffs if locations differ and available
    self.geoloc_diff = self.calc_geolocation_differ()

    self.ssh_available = ssh_available
    if ssh_keys: # { 4: { type: key }, 6: { type: key } }
      self.ssh4 = ssh_keys[4]
      self.ssh6 = ssh_keys[6]
      self.ssh_keys_match = self.keys_match()
    else:
      self.ssh_keys_match = None
      self.ssh4 = {}
      self.ssh6 = {}

    self.agent4 = ''
    self.agent6 = ''
    self.ssh_agents_match = None

    if trace_set_id: # trace set where the candidate belongs to [optional]
      self.trace_set_id = trace_set_id
    if trace_data:
      self.trace_data = trace_data


  def __hash__(self):
    return hash(self.ip4 + '_' + str(self.port4) + '_' + self.ip6 + '_' + str(self.port6))


  def __eq__(self, other):
    if isinstance(other, SiblingCandidate):
      return self.ip4 == other.ip4 and self.ip6 == other.ip6 and self.port4 == other.port4 and self.port6 == other.port6
    return NotImplemented


  def __str__(self):
    if getattr(self, 'trace_set_id', None):
      ts_id_str = ' - TraceSet ID: {0}'.format(self.trace_set_id)
    else:
      ts_id_str = ''
    p4_str = '({0})'.format(self.port4)
    p6_str = '({0})'.format(self.port6)
    return 'SiblingCandidate - {0:<15} {1:>7}   <=>   {3:<7} {2:<39}{4}'.format(self.ip4, p4_str, self.ip6, p6_str, ts_id_str)


  def has_ssh(self):
    return self.ssh_available

  def addsshkey(self, type, key, version):
    if version == const.IP4:
      self.ssh4[type] = key
    elif version == const.IP6:
      self.ssh6[type] = key


  def addsshkeys(self, keys, version):
    if version == const.IP4:
      self.ssh4 = keys # { type: key }
    elif version == const.IP6:
      self.ssh6 = keys # { type: key }
    else:
      return

    if self.ssh4 and self.ssh6: # check matching keys if both ssh key values set
      self.ssh_keys_match = self.keys_match()

  def keys_match(self):
    if not self.ssh4 or not self.ssh6:
      return None

    keytypes = set(self.ssh4.keys()).intersection(set(self.ssh6.keys()))

    if not keytypes:
      return None

    for type in keytypes:
      if self.ssh4[type] != self.ssh6[type]:
        return False

    return True


  def addsshagent(self, agent, version):
    if version == const.IP4:
      self.agent4 = agent.strip()
    elif version == const.IP6:
      self.agent6 = agent.strip()
    else:
      return None

    self.ssh_agents_match = self.agents_match()


  def agents_match(self):
    if not self.agent4 or not self.agent6:
      return None
    return self.agent4 == self.agent6


  def get_status(self):
    """
    -> (calculations_finished, sibling_status)
    """
    return (self.calc_finished, self.sibling_status)


  def plot(self, fname = None, func = None, funckwargs = None, title = None, titlefontsize = 10, xticks = None, xlabel = None, ylabel = None, legend = None):
    """
    Plots data to a matplotlib.pyplot figure.
    If domains are available, use the alphabetically first domain as plot title (as long as the title argument is omitted)

    fname           file name to write the figure to (use extension as format indicator)
    func            function which should be called with the figure (signature: [plt.Figure, **funckwargs])
    funckwargs      dict of kwargs intended to use with 'func' and unrolled with '**'
    title           plot title
    titlefontsize   font size to use for title
    xticks          array containing ticks for the x axis
    xlabel          array with x axis labels
    ylabel          array with y axis labels
    legend          dict containing kwargs used with plt.legend() (https://matplotlib.org/api/_as_gen/matplotlib.pyplot.legend.html)
    """
    if not self.calc_finished:
      log.warning('Calculations not finished for {0} / {1} - Nothing to plot ...'.format(self.ip4, self.ip6))
      return False

    if not (hasattr(self, 'cleaned_mean4') and hasattr(self, 'cleaned_mean6') and hasattr(self, 'spline_arr4') and hasattr(self, 'spline_arr6')):
      log.warning('No data to plot ... Ignoring {0} / {1}'.format(self.ip4, self.ip6))
      return False

    fig = plt.figure()
    axis1 = fig.add_subplot(111) # nrows, ncols, plot_number
    x4, y4 = zip(*self.cleaned_mean4)
    x6, y6 = zip(*self.cleaned_mean6)

    # 'bo' -> blue circles -> fmt parameter https://matplotlib.org/api/_as_gen/matplotlib.pyplot.plot.html
    axis1.plot(x4, y4, 'bo', color = 'blue', alpha = 0.4, label = 'IPv4')
    axis1.plot(x6, y6, 'bo', color = 'red', alpha = 0.4, label = 'IPv6')

    axis1.plot(self.xs4, self.spline_arr4, linewidth = 4, color = 'blue', alpha = 0.4)
    axis1.plot(self.xs6, self.spline_arr6, linewidth = 4, color = 'red', alpha = 0.4)

    if legend:
      plt.legend(**legend)
    else:
      plt.legend(loc = 'lower right')

    if title:
      plt.title(title, fontsize = titlefontsize)
    else:
      if self.domains:
        domain = sorted(list(self.domains))[0]
        titlestr = '{0}\n{1} / {2}'.format(domain, self.ip4, self.ip6)
      else:
        titlestr = '{0} / {1}'.format(self.ip4, self.ip6)
      plt.title(titlestr, fontsize = titlefontsize)

    if xlabel:
      plt.xlabel(xlabel)
    else:
      plt.xlabel('measurement time (h)')

    if ylabel:
      plt.ylabel(ylabel)
    else:
      plt.ylabel('observed offset (msec)')

    if xticks:
      axis1.set_xticklabels(xticks)
    else:
      ticks = axis1.get_xticks() / 3600 # set xticks on an hourly basis
      ticks = [ round(t, 1) for t in ticks ]
      axis1.set_xticklabels(ticks)

    if func:
      func(fig, **funckwargs)
    if fname:
      plt.savefig(fname)

    plt.close(fig)

    return True



  def get_features(self, key_list = None, substitute_none = None):
    """
    Return features used for machine learning.
    """
    if key_list:
      keys = key_list
    else:
      keys = [ 'hz4', 'hz6', 'hz_diff', 'hz4_R2', 'hz6_R2', 'hz_rsqrdiff', 'raw_timestamp_diff', 'alpha4', 'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'dynrange4', 'dynrange6', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel', 'spl_diff', 'spl_diff_scaled', 'ssh_keys_match', 'ssh_agents_match', 'geoloc_diff' ]

    features = {}
    for key in keys:
      features[key] = getattr(self, key, substitute_none)
    return features


  def get_results(self):
    """
    Return nearly all results of the calculations.
    """
    results = {}
    try:
      results['ip4'] = self.ip4
      results['ip6'] = self.ip6
      results['port4'] = self.port4
      results['port6'] = self.port6
      results['domains'] = getattr(self, 'domains', None)
      results['hz4'] = getattr(self, 'hz4', None)
      results['hz6'] = getattr(self, 'hz6', None)
      results['hz_diff'] = getattr(self, 'hz_diff', None)
      results['hz4_R2'] = getattr(self, 'hz4_R2', None)
      results['hz6_R2'] = getattr(self, 'hz6_R2', None)
      results['hz_rsqrdiff'] = getattr(self, 'hz_rsqrdiff', None)
      results['raw_ts_diff'] = getattr(self, 'raw_timestamp_diff', None)
      results['alpha4'] = getattr(self, 'alpha4', None)
      results['alpha6'] = getattr(self, 'alpha6', None)
      results['alphadiff'] = getattr(self, 'alphadiff', None)
      results['rsqr4'] = getattr(self, 'rsqr4', None)
      results['rsqr6'] = getattr(self, 'rsqr6', None)
      results['rsqrdiff'] = getattr(self, 'rsqrdiff', None)
      results['theta'] = getattr(self, 'theta', None)
      results['dynrange4'] = getattr(self, 'dynrange4', None)
      results['dynrange6'] = getattr(self, 'dynrange6', None)
      results['dynrange_avg'] = getattr(self, 'dynrange_avg', None)
      results['dynrange_diff'] = getattr(self, 'dynrange_diff', None)
      results['dynrange_diff_rel'] = getattr(self, 'dynrange_diff_rel', None)
      results['spl_mean4'] = getattr(self, 'spl_mean4', None)
      results['spl_mean6'] = getattr(self, 'spl_mean6', None)
      results['spl_diff'] = getattr(self, 'spl_diff', None)
      results['spl_diff_scaled'] = getattr(self, 'spl_diff_scaled', None)
      results['spl_percent_val'] = getattr(self, 'spl_percent_val', None) # perc_85_val
      results['ip4_tcpopts'] = getattr(self, 'ip4_tcpopts', None)
      results['ip6_tcpopts'] = getattr(self, 'ip6_tcpopts', None)
      results['status'] = getattr(self, 'sibling_status', None)
      results['is_sibling'] = getattr(self, 'is_sibling', None)
      results['geo4'] = getattr(self, 'geo4', None)
      results['geo6'] = getattr(self, 'geo6', None)
      results['geoloc_diff'] = getattr(self, 'geoloc_diff', None)
      results['ssh_keys_match'] = getattr(self, 'ssh_keys_match', None)
      results['ssh_agents_match'] = getattr(self, 'ssh_agents_match', None)
    except Exception as e:
      log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
      return None

    return results



  def evaluate(self):
    if self.calc_finished:
      log.warning('Already evaluated SiblingCandidate (result: {0}) {1} / {2} -> {3}'.format(self.is_sibling, self.ip4, self.ip6, self.sibling_status))
      return self.is_sibling

    # check ssh keys
    self.ssh_keys_match = self.keys_match()
    self.ssh_agents_match = self.agents_match()

    # start sibling calculations
    # set sibling_status each step by calling calculations and stop on error
    try:

      # TCP options check
      # if self.tcp_opts_differ is None:
      #   log.warning('Ignoring TCP options (not available) for {0} / {1}'.format(self.ip4, self.ip6))
      # elif self.tcp_opts_differ == True:
      #   raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_TCP_OPTIONS_DIFFER)


      # frequency calculation
      if not self.calc_frequency():
        # set status and hz4, Xi4, Vi4, hz4_R2, hz4_raw; hz6, Xi6, Vi6, hz6_R2, hz6_raw
        raise SiblingEvaluationError()

      # calculate and check raw tcp timestamp value
      if not self.calc_raw_tcp_timestamp_value():
        # sets raw_timestamp_diff
        log.error('Raw TCP timestamp difference calculation error')
        raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_RAW_TS_DISTANCE_ERROR)

      # DO NOT DECIDE HERE => ML should do this!
      # # check v4/v6 frequencies and r-squared match
      # if self.hz_diff > const.SIB_FREQ_HZ_DIFF_MAX or self.hz_rsqrdiff > const.SIB_FREQ_R2_DIFF_MAX:
      #   log.error('Frequency difference too high')
      #   raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_FREQ_DIFF_TOO_HIGH)


      if const.SIB_FRT_CALC_ADDITIONAL_FEATURES:

        # offset calculations
        if not self.calc_time_offsets():
          # set status and tcp_ts_offsets4, tcp_ts_offsets6
          raise SiblingEvaluationError()

        # denoise calculations
        if not self.calc_denoise():
          # set status and denoised4 and denoised6
          raise SiblingEvaluationError()

        # calculate outlier removal
        if not self.calc_outlier_removal():
          log.error('Mean removal error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_MEAN_REMOVAL_ERROR)

        if not self.calc_pairwise_point_distance():
          log.error('Pairwise point distance calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_PPD_ERROR)

        if not self.calc_ppd_mean_median_thresholds():
          log.error('PPD mean/median threshold calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_PPD_THRESHOLD_ERROR)

        if not self.calc_sigma_outlier_removal():
          log.error('Two sigma outlier removal calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_SIGMA_OUTLIER_REMOVAL_ERROR)

        if not self.calc_dynamic_range():
          log.error('Dynamic range calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_DYNAMIC_RANGE_ERROR)

        if not self.calc_alpha(): # skew angle
          log.error('Angle alpha calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_ALPHA_ERROR)

        if not self.calc_theta(): # Beverly Section 3.3; the angle between the lines built by drawing alpha4/alpha6
          log.error('Theta calculation error') # if theta < tau (threshold value = 1.0) then inferred to be siblings
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_THETA_ERROR)


      if const.SIB_FRT_CALC_SPLINE:

        if not self.calc_spline():
          log.error('Spline calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_SPLINE_CALC_ERROR)

        if not self.calc_curve_mapping():
          log.error('Curve mapping calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_CURVE_MAPPING_ERROR)

        if not self.calc_curve_diff_percent():
          log.error('Curve percentage mapping calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_CURVE_PERCENT_MAPPING_ERROR)


    except SiblingEvaluationError as e:
      self.calc_error = True
      if e.sibling_status is not None:
        self.sibling_status = e.sibling_status
    finally:
      self.calc_finished = True

      # always check if we can determine sibling status based on raw ts val diff
      raw_ts_diff = getattr(self, 'raw_timestamp_diff', None)

      # TODO: ask ml model or other algorithms for sibling decision

      if raw_ts_diff and raw_ts_diff <= SiblingCandidate.TS_DIFF_THRESHOLD: # sibling based on raw ts val diff
        if self.calc_error: # if calc_error occurred we append the status message
          self.sibling_status = '{0},{1}'.format(self.sibling_status, const.SIB_STATUS_IS_SIBLING_RAW_TS_VAL_DIFF)
        else:
          self.sibling_status = const.SIB_STATUS_IS_SIBLING_RAW_TS_VAL_DIFF
        self.is_sibling = True
        return True
      else:
        # no sibling
        if self.calc_error: # if calc_error occurred we append the status message
          self.sibling_status = '{0},{1}'.format(self.sibling_status, const.SIB_STATUS_IS_NO_SIBLING)
        else:
          self.sibling_status = const.SIB_STATUS_IS_NO_SIBLING
        self.is_sibling = False
        return False



  def calc_tcp_opts_differ(self):
    # e.g. [('MSS', 1360), ('NOP', None), ('NOP', None), ('Timestamp', (453053021, 1337)), ('NOP', None), ('WScale', 8)]
    # Paper TCP options format: 'MSS-SACK-TS-N-WS03-'
    # MSS -> Max Segment Size; SACK -> Selective ACK, TS -> TimeStamp, N -> Nop, WS03 -> WindowScale factor 3
    # CHECK: presence, option order, nop padding bytes, window scale value (if present)

    if not all([self.ip4_tcpopts, self.ip6_tcpopts]):
      return None

    opt4 = iter(self.ip4_tcpopts)
    opt6 = iter(self.ip6_tcpopts)

    while True:
      o4 = next(opt4, None)
      o6 = next(opt6, None)

      if not o4 and not o6:
        return False # options matched until now -> finished

      if o4 and not o6:
        log.debug('Missing TCP option in IPv6: {0}'.format(o4[0]))
        return True
      if not o4 and o6:
        log.debug('Missing TCP option in IPv4: {0}'.format(o6[0]))
        return True

      if o4[0] != o6[0]:
        log.debug('TCP options are ordered differently - IPv4: {0} / IPv6: {1}'.format(o4[0], o6[0]))
        return True

      if o4[0] == 'WScale': # at this point we can be sure that ip6 as well as ip4 options are the same
        if o4[1] != o6[1]:
          log.debug('Window Scale option factor does not match - IPv4: {0} / IPv6: {1}'.format(o4[1], o6[1]))
          return True


  def calc_geolocation_differ(self, geoloc_obj = None):
    geo = None
    # const.GEO > geoloc_obj
    if geoloc_obj:
      geo = geoloc_obj
    if const.GEO:
      geo = const.GEO
    if not geo:
      return None

    match, diffs, data4, data6 = geo.match(self.ip4, self.ip6, get_diffs = True)
    if match is None: # explicitly test for None if information was not available
      self.geodiffs = None
      return None

    self.geo4 = '-'.join([ str(v) if v != None else '?' for v in data4.values() ]) # country_iso_code-continent_code
    self.geo6 = '-'.join([ str(v) if v != None else '?' for v in data6.values() ])

    if not match:
      s = []
      for k, v in diffs.items():
        s.append('{0} <-> {1}'.format(v[0], v[1]))
      log.debug('Geolocation differs - {0} / {1} - {2}'.format(self.ip4, self.ip6, ', '.join(s)))
      self.geodiffs = diffs
      return match
    else:
      self.geodiffs = None
      return match


  def _calc_frequency(self, ipversion = None):
    if ipversion == 4:
      recv_ts = self.ip4_ts['received']
      tcp_ts = self.ip4_ts['remote']
      offset_recv = self.recv_offset4
      offset_tcp = self.tcp_offset4
    elif ipversion == 6:
      recv_ts = self.ip6_ts['received']
      tcp_ts = self.ip6_ts['remote']
      offset_recv = self.recv_offset6
      offset_tcp = self.tcp_offset6
    else:
      return (None, None, None, None, None)

    nr_timestamps = len(recv_ts) # already identical length

    Xi_arr = numpy.zeros(nr_timestamps - 1)
    Vi_arr = numpy.zeros(nr_timestamps - 1)

    adjustment_recv = 0
    adjustment_tcp = 0
    for i in range(1, nr_timestamps):

      # in doubt, also do this for packet receive timestamps
      if recv_ts[i] + const.SIB_TS_OVERFLOW_THRESHOLD < recv_ts[i - 1]:
        if recv_ts[i - 1] > 2**31:
          adjustment_recv = 2**32
      xi = recv_ts[i] + adjustment_recv - offset_recv

      if tcp_ts[i] + const.SIB_TS_OVERFLOW_THRESHOLD < tcp_ts[i - 1]:
        if tcp_ts[i - 1] > 2**31:
          adjustment_tcp = 2**32
      vi = tcp_ts[i] + adjustment_tcp - offset_tcp

      Xi_arr[i - 1] = xi
      Vi_arr[i - 1] = vi

    # We do not check monotonicity -> check rval**2 instead -> if low -> probably randomized timestamps
    ############################################################################
    # https://stackoverflow.com/a/10996196
    # diff = numpy.diff(Vi_arr)
    # indices = []
    # for i, val in enumerate(diff):
    #   if val < 1:
    #     indices.append(i)
    #
    # if len(indices) >= int(len(Vi_arr) * const.SIB_TS_MONOTONICITY_PERCENTAGE):
    #   log.error('IPv{0} error: more than {1}% of timestamps to be removed for strict monotonicity!'.format(ipversion, int(const.SIB_TS_MONOTONICITY_PERCENTAGE * 100)))
    #   return (None, None, None, None, None)
    #
    # Xi_arr = numpy.delete(Xi_arr, indices)
    # Vi_arr = numpy.delete(Vi_arr, indices)

    # numpy.all(numpy.diff(Vi_arr) >= 0) # probably more elegant way but returns new array with diffs (slicing only uses array views (twice as fast!))
    # if not numpy.all(Vi_arr[1:] >= Vi_arr[:-1]): # non-monotonic after adjustment -> probably randomized timestamps
    #   return (None, None, None, None, None)
    ############################################################################
    ############################################################################

    # perform regression
    slope_raw, intercept, rval, pval, stderr = stats.linregress(Xi_arr, Vi_arr)
    hz_R2 = rval * rval # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
    hz = round(slope_raw) # Kohno et al. Section 4.3

    return (hz, Xi_arr, Vi_arr, hz_R2, slope_raw)

  def calc_frequency(self):
    hz4, Xi4, Vi4, hz4_R2, hz4_raw = self._calc_frequency(ipversion = 4)
    hz6, Xi6, Vi6, hz6_R2, hz6_raw = self._calc_frequency(ipversion = 6)

    # not necessary anymore -> randomization can be checked by inspecting rval**2
    # if not hz4 and not hz6:
    #   self.sibling_status = const.SIB_STATUS_ALL_RANDOMIZED_TS
    #   log.error('Both IPs probably randomized timestamps: {0} / {1}'.format(self.ip4, self.ip6))
    #   return False
    #
    # if not hz4:
    #   self.sibling_status = const.SIB_STATUS_IP4_RANDOMIZED_TS
    #   log.error('IPv4 - Probably randomized timestamps: {0} / {1}'.format(self.ip4, self.ip6))
    #   return False
    #
    # if not hz6:
    #   self.sibling_status = const.SIB_STATUS_IP6_RANDOMIZED_TS
    #   log.error('IPv6 - Probably randomized timestamps: {0} / {1}'.format(self.ip4, self.ip6))
    #   return False

    # DO NOT DECIDE HERE => just plain calculations
    # if abs(hz4_raw) < const.SIB_FREQ_IP4_MIN and abs(hz6_raw) < const.SIB_FREQ_IP6_MIN:
    #   self.sibling_status = const.SIB_STATUS_ALL_FREQ_TOO_LOW
    #   log.error('Both IPs frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
    #   return False
    #
    # if abs(hz4_raw) < const.SIB_FREQ_IP4_MIN:
    #   self.sibling_status = const.SIB_STATUS_IP4_FREQ_TOO_LOW
    #   log.error('IPv4 - frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
    #   return False
    #
    # if abs(hz6_raw) < const.SIB_FREQ_IP6_MIN:
    #   self.sibling_status = const.SIB_STATUS_IP6_FREQ_TOO_LOW
    #   log.error('IPv6 - frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
    #   return False
    #
    # if hz4_R2 < const.SIB_FREQ_IP4_R2_MIN and hz6_R2 < const.SIB_FREQ_IP6_R2_MIN:
    #   self.sibling_status = const.SIB_STATUS_ALL_R2_TOO_LOW
    #   log.error('Both IPs r-squared below defined threshold - maybe randomized TS ({0} / {1}): {2} / {3}'.format(hz4_R2, hz6_R2, self.ip4, self.ip6))
    #   return False
    #
    # if hz4_R2 < const.SIB_FREQ_IP4_R2_MIN:
    #   self.sibling_status = const.SIB_STATUS_IP4_R2_TOO_LOW
    #   log.error('IPv4 - r-squared below defined threshold (< {0}) - maybe randomized TS: {1} / {2}'.format(const.SIB_FREQ_IP4_R2_MIN, self.ip4, self.ip6))
    #   return False
    #
    # if hz6_R2 < const.SIB_FREQ_IP6_R2_MIN:
    #   self.sibling_status = const.SIB_STATUS_IP6_R2_TOO_LOW
    #   log.error('IPv6 - r-squared below defined threshold (< {0}) - maybe randomized TS: {1} / {2}'.format(const.SIB_FREQ_IP6_R2_MIN, self.ip4, self.ip6))
    #   return False


    self.hz4, self.Xi4, self.Vi4, self.hz4_R2, self.hz4_raw = hz4, Xi4, Vi4, hz4_R2, hz4_raw
    self.hz6, self.Xi6, self.Vi6, self.hz6_R2, self.hz6_raw = hz6, Xi6, Vi6, hz6_R2, hz6_raw
    self.hz_diff = abs(self.hz4_raw - self.hz6_raw)
    self.hz_rsqrdiff = abs(self.hz4_R2 - self.hz6_R2)
    return True


  def calc_raw_tcp_timestamp_value(self):
    try:
      # tcp time distance in seconds
      tcp_time_distance = (self.tcp_offset6 - self.tcp_offset4) / numpy.mean([self.hz4_raw, self.hz6_raw]) # both are numpy.int64
      recv_time_distance = self.recv_offset6 - self.recv_offset4 # both are numpy.float64
      raw_timestamp_diff = abs(tcp_time_distance - recv_time_distance)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    self.raw_timestamp_diff = raw_timestamp_diff
    return True


  def _calc_time_offsets(self, ipversion = None):
    if ipversion == 4:
      Xi = self.Xi4
      Vi = self.Vi4
      hz = self.hz4
    elif ipversion == 6:
      Xi = self.Xi6
      Vi = self.Vi6
      hz = self.hz6
    else:
      return None

    offsets = None

    Wi = [ round(float(vi) / hz, 6) for vi in Vi ] # seconds with microseconds precision
    Yi = [ (wi - xi) * 1000 for wi, xi in zip(Wi, Xi) ] # offset in milliseconds
    offsets = numpy.array([ (round(x, 6), round(y, 6)) for x, y in zip(Xi, Yi) ])

    return offsets

  def calc_time_offsets(self):
    offset_arr4 = self._calc_time_offsets(ipversion = 4)
    offset_arr6 = self._calc_time_offsets(ipversion = 6)

    if offset_arr4 is None and offset_arr6 is None:
      self.sibling_status = const.SIB_STATUS_ALL_OFFSET_ARRAY_ERROR
      log.error('Both IPs error during offset array construction: {0} / {1}'.format(self.ip4, self.ip6))
      return False

    if offset_arr4 is None:
      self.sibling_status = const.SIB_STATUS_IP4_OFFSET_ARRAY_ERROR
      log.error('IPv4 - error during offset array construction: {0} / {1}'.format(self.ip4, self.ip6))
      return False

    if offset_arr6 is None:
      self.sibling_status = const.SIB_STATUS_IP6_OFFSET_ARRAY_ERROR
      log.error('IPv6 - error during offset array construction: {0} / {1}'.format(self.ip4, self.ip6))
      return False

    self.tcp_ts_offsets4, self.tcp_ts_offsets6 = offset_arr4, offset_arr6
    return True


  def _calc_denoise(self, ipversion = None):
    # Divide all probes at hourly intervals to a list.
    # Take the minimum of the hourly tcp offset value (y val)
    # add the corresponding received time (x val) to min_arr.
    if ipversion == 4:
      offsets = self.tcp_ts_offsets4
    elif ipversion == 6:
      offsets = self.tcp_ts_offsets6
    else:
      return None

    recv_times, tcp_offsets = zip(*offsets) # zip applied to numpy array returns tuples
    recv_times_length = len(recv_times)

    start = 0
    end = 120
    const_multiplier = 120
    n = 1
    # hold_x = 0 # really necessary?
    # hold_y = 0 # really necessary?

    recv_times_per_h = [] # hold all receive times within the current hour
    tcp_offsets_per_h = [] # hold all offsets within the current hour
    all_recv_times = [] # holds all hour based lists
    all_tcp_offsets = [] # holds all hour based lists

    for ctr, current_recv_time in enumerate(recv_times, 1):
      if start <= current_recv_time < end:
        recv_times_per_h.append(current_recv_time)
        tcp_offsets_per_h.append(tcp_offsets[ctr - 1])
      else:
        # hold_x = current_recv_time
        # hold_y = tcp_offsets[ctr - 1]

        all_recv_times.append(recv_times_per_h)
        all_tcp_offsets.append(tcp_offsets_per_h)
        recv_times_per_h = []
        tcp_offsets_per_h = []
        recv_times_per_h.append(current_recv_time) # hold_x
        tcp_offsets_per_h.append(tcp_offsets[ctr - 1]) # hold_y

        start = end
        n = n + 1
        end = n * const_multiplier

      if ctr == recv_times_length and tcp_offsets_per_h: # do not forget to add the last hour list (if not empty)
        all_recv_times.append(recv_times_per_h)
        all_tcp_offsets.append(tcp_offsets_per_h)

    min_arr = [] # collect min values from hour based lists

    for i in range(len(all_tcp_offsets)):
      try: # get the index of the min value within the current hour
        index = numpy.array(all_tcp_offsets[i]).argmin()
      except ValueError as e:
        log.error('[{ip4} / {ip6}] ValueError at argmin(): {0}'.format(e, ip4 = self.ip4, ip6 = self.ip6))
        return None

      min_per_probe = all_tcp_offsets[i][index]
      corresponding_x_per_probe = all_recv_times[i][index]
      min_arr.append((corresponding_x_per_probe, min_per_probe))

    return min_arr

  def calc_denoise(self):
    denoised4 = self._calc_denoise(ipversion = 4)
    denoised6 = self._calc_denoise(ipversion = 6)

    if denoised4 is None and denoised6 is None:
      self.sibling_status = const.SIB_STATUS_ALL_DENOISED_ARRAY_ERROR
      log.error('Both IPs error during denoised array construction: {0} / {1}'.format(self.ip4, self.ip6))
      return False

    if denoised4 is None:
      self.sibling_status = const.SIB_STATUS_IP4_DENOISED_ARRAY_ERROR
      log.error('IPv4 - error during denoised array construction: {0} / {1}'.format(self.ip4, self.ip6))
      return False

    if denoised6 is None:
      self.sibling_status = const.SIB_STATUS_IP6_DENOISED_ARRAY_ERROR
      log.error('IPv6 - error during denoised array construction: {0} / {1}'.format(self.ip4, self.ip6))
      return False

    self.denoised4 = denoised4
    self.denoised6 = denoised6
    return True


  def _calc_outlier_removal(self, ipversion = None):
    # remove outliers off the confidence level
    if ipversion == 4:
      offsets = self.denoised4
    elif ipversion == 6:
      offsets = self.denoised6
    else:
      log.error('Invalid ipversion provided')
      return None

    y_vals = [ y for x, y in offsets ]

    with numpy.errstate(invalid = 'raise'):
      try:
        mean = numpy.mean(y_vals)
        stddev = numpy.std(y_vals) # may raise numpy warning for malformed array
      except Exception as e:
        log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))

    lower, upper = (mean - const.SIB_Z_SCORE_CONFIDENCE_LEVEL_97 * stddev, mean + const.SIB_Z_SCORE_CONFIDENCE_LEVEL_97 * stddev)
    cleaned_arr = []

    for value_pair in offsets: # list of tuples
      if value_pair[1] < lower or value_pair[1] > upper:
        continue
      cleaned_arr.append(value_pair)

    return cleaned_arr

  def calc_outlier_removal(self):
    cleaned_mean4 = self._calc_outlier_removal(ipversion = 4)
    cleaned_mean6 = self._calc_outlier_removal(ipversion = 6)

    if cleaned_mean4 and cleaned_mean6:
      self.cleaned_mean4 = cleaned_mean4
      self.cleaned_mean6 = cleaned_mean6
      return True
    else:
      return False


  def calc_pairwise_point_distance(self):
    # Calculate pairwise point distance between candidate offset values
    x4, y4 = zip(*self.cleaned_mean4)
    x6, y6 = zip(*self.cleaned_mean6)

    max_index = min(len(x4), len(x6)) # if one of the IPs stop responding -> different offset array size

    np_x6 = numpy.array(x6)
    index6_arr = [] # holds the indices of the closest IPv6 arrival times relative to every IPv4 arrival time
    ppd_arr = []

    for index in range(max_index): # find the closest arrival time for IPv6 being sj6 (index) to that of IPv4 si4 (closest arrival time)
      try:
        index6 = numpy.abs(np_x6 - x4[index]).argmin()
      except Exception as e: # ValueError
        log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
        return False

      index6_arr.append(index6)

    for index4 in range(max_index): # get y values for those pair of points and calculate the absolute pairwise distance
      try:
        si4 = y4[index4]
        sj6 = y6[index6_arr[index4]]
        ppd_arr.append(abs(si4 - sj6))
      except Exception as e:
        log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
        return False

    global_min = min(min(y4), min(y6))
    global_max = max(max(y4), max(y6))
    range_ymin_ymax = abs(global_min - global_max) # range between the smallest and biggest value observed

    self.ppd_arr, self.ppd_index6_arr, self.ppd_range_raw = ppd_arr, index6_arr, range_ymin_ymax
    return True


  def calc_ppd_mean_median_thresholds(self):
    mad_lst = []  # median absolute deviation
    try:
      mean = numpy.mean(self.ppd_arr)
      stddev_mean = numpy.std(self.ppd_arr)
      median = numpy.median(self.ppd_arr)

      for point in self.ppd_arr:
          mad_lst.append(abs(point - median)) # median absolute deviation

      # https://en.wikipedia.org/wiki/Median_absolute_deviation#Relation_to_standard_deviation
      stddev_median = const.SIB_CONSISTENCY_CONSTANT_K * numpy.median(mad_lst)

      median_threshhold = (median - const.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stddev_median, median + const.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stddev_median)
      mean_threshhold = (mean - const.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stddev_mean, mean + const.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stddev_mean)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    self.ppd_mean_threshold, self.ppd_median_threshold = mean_threshhold, median_threshhold
    return True


  def calc_sigma_outlier_removal(self):
    clean4 = []
    clean6 = []
    arr6 = []
    ppd_arr_pruned = []

    try:
      lower, upper = self.ppd_median_threshold

      for index6 in self.ppd_index6_arr:
        arr6.append(self.cleaned_mean6[index6])

      for i in range(len(self.ppd_arr)):
        if not self.ppd_arr[i] < lower and not self.ppd_arr[i] > upper:
          clean4.append(self.cleaned_mean4[i])
          clean6.append(arr6[i])
          ppd_arr_pruned.append(self.ppd_arr[i])

      self.ppd_range_pruned = max(ppd_arr_pruned) - min(ppd_arr_pruned)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    self.cleaned_mean4_sigma, self.cleaned_mean6_sigma = clean4, clean6
    self.ppd_arr_pruned = ppd_arr_pruned
    return True


  def _calc_alpha(self, ipversion = None):
    if ipversion == 4:
      offset_arr = self.cleaned_mean4_sigma
    elif ipversion == 6:
      offset_arr = self.cleaned_mean6_sigma
    else:
      log.error('Invalid ipversion provided')
      return None

    x_arr, y_arr = zip(*offset_arr)

    try:
      slope_raw, intercept, rval, pval, stderr = stats.linregress(x_arr, y_arr)
      medslope, medintercept, lo_slope, up_slope = stats.mstats.theilslopes(y_arr, x_arr)
    # except FloatingPointError as e:
    #   log.error('[{ip4} / {ip6}] Exception: {0}'.format(e, ip4 = self.ip4, ip6 = self.ip6))
    #   return None
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return None

    return (medslope, medintercept, rval, rval ** 2)

  def calc_alpha(self):
    ret4 = self._calc_alpha(ipversion = 4)
    ret6 = self._calc_alpha(ipversion = 6)

    if not ret4 or not ret6:
      return False

    alpha4, _, _, r4_sqr = ret4
    alpha6, _, _, r6_sqr = ret6

    try:
      alphadiff = abs(alpha4 - alpha6)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    try:
      rsqrdiff = abs(r4_sqr - r6_sqr)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    self.alpha4, self.alpha6, self.alphadiff = alpha4, alpha6, alphadiff
    self.rsqr4, self.rsqr6, self.rsqrdiff = r4_sqr, r6_sqr, rsqrdiff
    return True


  def calc_theta(self):
    try:
      fraction = (self.alpha4 - self.alpha6) / (1 + self.alpha4 * self.alpha6)
      theta = numpy.arctan(abs(fraction))
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    self.theta = theta
    return True


  def _calc_dynamic_range(self, ipversion = None):
    # prune 2.5% form upper and lower array content and calculate range between lowest and highest value
    if ipversion == 4:
      offset_arr = self.cleaned_mean4_sigma
    elif ipversion == 6:
      offset_arr = self.cleaned_mean6_sigma
    else:
      log.error('Invalid ipversion provided')
      return None

    try:
      offsets = sorted([ y for _, y in offset_arr ])
      length = len(offsets)
      lower_index = int(round((const.SIB_DYNRNG_LOWER_CUT_PERCENT * length) / 100))
      upper_index = int(round((const.SIB_DYNRNG_UPPER_CUT_PERCENT * length) / 100))

      low_val = offsets[lower_index]
      high_val = offsets[upper_index - 1]
      range = high_val - low_val
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return None

    return range

  def calc_dynamic_range(self):
    dynrange4 = self._calc_dynamic_range(ipversion = 4)
    dynrange6 = self._calc_dynamic_range(ipversion = 6)

    if not dynrange4 or not dynrange6:
      return False

    try:
      dynrange_diff = abs(dynrange4 - dynrange6)
      dynrange_avg = numpy.mean([dynrange4, dynrange6])
      dynrange_diff_rel = dynrange_diff / dynrange_avg
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    self.dynrange4, self.dynrange6 = dynrange4, dynrange6
    self.dynrange_diff, self.dynrange_diff_rel = dynrange_diff, dynrange_diff_rel
    self.dynrange_avg = dynrange_avg
    return True


  #### SPLINE calculations
  ##############################################################################
  def _calc_equal_bin_size(self, offsets, nr_bins):
    start = offsets[0][0] # list(tuple(x, y))
    stop = offsets[-1][0]
    return round((stop - start) / nr_bins, 1)

  def _calc_spline(self, bin_size, packed_arr):
    try:
      x, y = zip(*packed_arr)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return None

    xs = numpy.arange(x[0], x[-1], const.SIB_SPLINE_XSPLINE_SPACING)

    knots = [ x[0] + i * bin_size for i in range(1, const.SIB_SPLINE_NR_BINS) ]

    try:
      # according to scipy docs removing first and last knot
      # https://docs.scipy.org/doc/scipy/reference/generated/scipy.interpolate.LSQUnivariateSpline.html
      spl = interpolate.LSQUnivariateSpline(x, y, knots[1:-1], w = None, bbox = [None, None], k = const.SIB_SPLINE_DEGREE)
      curve = spl(xs)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return None

    return (curve, xs)

  def calc_spline(self):
    try:
      bin_size4 = self._calc_equal_bin_size(self.cleaned_mean4_sigma, const.SIB_SPLINE_NR_BINS)
      bin_size6 = self._calc_equal_bin_size(self.cleaned_mean6_sigma, const.SIB_SPLINE_NR_BINS)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    if not bin_size4 or not bin_size6:
      return False

    self.bin_size4, self.bin_size6 = bin_size4, bin_size6
    # eliminate first and last points for spline computation
    packed4 = self.cleaned_mean4_sigma[const.SIB_SPLINE_LOWER_POINTS_INDEX : const.SIB_SPLINE_UPPER_POINTS_INDEX]
    packed6 = self.cleaned_mean6_sigma[const.SIB_SPLINE_LOWER_POINTS_INDEX : const.SIB_SPLINE_UPPER_POINTS_INDEX]

    res4 = self._calc_spline(self.bin_size4, packed4)
    res6 = self._calc_spline(self.bin_size6, packed6)

    if not res4 or not res6:
      return False

    self.spline_arr4, self.xs4 = res4
    self.spline_arr6, self.xs6 = res6
    return True


  def calc_curve_mapping(self):
    # map the upper curve on the lower one
    try:
      spl_mean4 = numpy.mean(self.spline_arr4)
      spl_mean6 = numpy.mean(self.spline_arr6)
      spl_diff = spl_mean4 - spl_mean6
      max_length = min(len(self.xs4), len(self.xs6))
      spl_mapped_diff = []

      if spl_diff > 0:
        y_mapped = self.spline_arr4[:max_length] - spl_diff
      else:
        y_mapped = self.spline_arr6[:max_length] - abs(spl_diff)

      if spl_diff >= 0: # v4 curve is the upper one
        x_mapped = self.xs4[:max_length]
        for i in range(max_length):
          spl_mapped_diff.append(abs(y_mapped[i] - self.spline_arr6[i]))
      else: # v6 curve is the upper one
        x_mapped = self.xs6[:max_length]
        for i in range(max_length):
          spl_mapped_diff.append(abs(y_mapped[i] - self.spline_arr4[i]))
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    self.spl_mapped_diff = spl_mapped_diff
    self.spl_mean4, self.spl_mean6 = spl_mean4, spl_mean6
    self.spl_diff = abs(spl_diff)
    self.spl_diff_scaled = spl_diff / self.dynrange_diff
    return True

  def calc_curve_diff_percent(self):
    # calc cumulative distribution function array first
    try:
      spl_counter = collections.Counter(self.spl_mapped_diff)
      keys = list(spl_counter.keys())
      counts = list(spl_counter.values())
      total_counts = sum(counts)
      percents = [ 100 * (c / total_counts) for c in counts ]
      appearances = sorted(spl_counter.items()) # -> returns list of tuples

      suml = 0
      cdf_arr = []

      for val, count in appearances:
        suml = suml + count
        cdf_arr.append((val, suml))

      perc_arr = []
      for val, perc in cdf_arr:
        if const.SIB_SPLINE_LOWER_PERCENT_MAPPING <= perc <= const.SIB_SPLINE_UPPER_PERCENT_MAPPING:
          perc_arr.append(val)

      # use percentil diff as metric
      mid_index = int(round(len(perc_arr) / 2))
      perc_val = perc_arr[mid_index]
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    self.spl_percent_val = perc_val
    return True


################################################################################
################################################################################

class LowRTSiblingCandidate(SiblingCandidate):

  def __init__(self, ip4, ip6, port4, port6, ip4_ts, ip6_ts, ip4_tcpopts, ip6_tcpopts, nr_timestamps = None, domains = None, ssh_available = False, ssh_keys = None, trace_set_id = None, trace_data = None):
    # Limit the number of timestamps with nr_timestamps to have all candidates the same amount of timestamps for evaluation

    self.sibling_status = const.SIB_STATUS_UNKNOWN
    self.calc_finished = False # flag to check if calculations have finished (due to error or valid result)
    self.is_sibling = False
    self.calc_error = False # flag to check if exception occurred -> correct status assignment

    self.ip4 = ip4
    self.ip6 = ip6
    self.port4 = port4
    self.port6 = port6
    self.ip4_tcpopts = ip4_tcpopts
    self.ip6_tcpopts = ip6_tcpopts
    self.domains = domains # may be None

    dt = numpy.dtype('int64, float64') # data type for numpy array
    columns = ['remote', 'received'] # column/index name -> e.g. access with ip4_ts['remote']
    dt.names = columns

    if nr_timestamps and nr_timestamps > 1:
      self.ip4_ts = numpy.array(ip4_ts[:nr_timestamps], dtype = dt)
      self.ip6_ts = numpy.array(ip6_ts[:nr_timestamps], dtype = dt)
      self.number_of_timestamps = nr_timestamps
    else:
      self.ip4_ts = numpy.array(ip4_ts, dtype = dt)
      self.ip6_ts = numpy.array(ip6_ts, dtype = dt)
      self.number_of_timestamps = min(len(self.ip4_ts), len(self.ip6_ts))

    self.recv_offset4 = self.ip4_ts['received'][0] # timestamp data e.g. 1541886109.485699 (float)
    self.recv_offset6 = self.ip6_ts['received'][0]
    self.tcp_offset4 = self.ip4_ts['remote'][0] # timestamp data e.g. 1541886109 (uint32)
    self.tcp_offset6 = self.ip6_ts['remote'][0]

    self.tcp_opts_differ = self.calc_tcp_opts_differ() # if None, no tcp options are available -> ignore
    # if None, no geo information available; additionally, fills self.geodiffs if locations differ and available
    self.geoloc_diff = self.calc_geolocation_differ()

    self.ssh_available = ssh_available
    if ssh_keys: # { 4: { type: key }, 6: { type: key } }
      self.ssh4 = ssh_keys[4]
      self.ssh6 = ssh_keys[6]
      self.ssh_keys_match = self.keys_match()
    else:
      self.ssh_keys_match = None
      self.ssh4 = {}
      self.ssh6 = {}

    self.agent4 = ''
    self.agent6 = ''
    self.ssh_agents_match = None

    if trace_set_id: # trace set where the candidate belongs to [optional]
      self.trace_set_id = trace_set_id
    if trace_data:
      self.trace_data = trace_data


  def get_features(self, key_list = None, substitute_none = None):
    """
    Return features used for machine learning.
    """
    if key_list:
      keys = key_list
    else:
      keys = [ 'hz4', 'hz6', 'hz_diff', 'hz4_R2', 'hz6_R2', 'hz_rsqrdiff', 'raw_timestamp_diff', 'alpha4', 'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'dynrange4', 'dynrange6', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel', 'spl_diff', 'spl_diff_scaled', 'ssh_keys_match', 'ssh_agents_match', 'geoloc_diff' ]

    features = super().get_features(key_list = keys, substitute_none = substitute_none)

    if not const.SIB_LOWRT_CALC_SPLINE or self.number_of_timestamps < const.SIB_LOWRT_MIN_TIMESTAMPS_FULL_CALC:
      try:
        del(features['spl_diff'])
        del(features['spl_diff_scaled'])
      except:
        pass

    if not const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES: # or self.number_of_timestamps < const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES_MIN_TIMESTAMPS:
      keys = [ 'alpha4', 'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'dynrange4', 'dynrange6', 'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel' ]
      for key in keys:
        try:
          del(features[key])
        except:
          continue

    return features


  def _calc_frequency(self, ipversion = None):
    if ipversion == 4:
      recv_ts = self.ip4_ts['received']
      tcp_ts = self.ip4_ts['remote']
      offset_recv = self.recv_offset4
      offset_tcp = self.tcp_offset4
    elif ipversion == 6:
      recv_ts = self.ip6_ts['received']
      tcp_ts = self.ip6_ts['remote']
      offset_recv = self.recv_offset6
      offset_tcp = self.tcp_offset6
    else: # should never happen
      return (None, None, None, None, None)

    nr_timestamps = len(recv_ts) # already identical length

    if nr_timestamps <= 2: # if we only have <= 2 timestamps available
      if not nr_timestamps > 0:
        log.error('IPv{0}: not enough timestamps available - {1} / {2}'.format(ipversion, self.ip4, self.ip6))
        return (None, None, None, None, None)

      tcp_diff = tcp_ts[1] - offset_tcp
      if tcp_diff == 0:
        log.error('IPv{0}: received identical remote timestamps, linregress not possible for {1} / {2}'.format(ipversion, self.ip4, self.ip6))
        return (None, None, None, None, None)

      # do linreg with offset value and the only timestamp in the array
      Xi_arr = numpy.array([0, recv_ts[1] - offset_recv])
      Vi_arr = numpy.array([0, tcp_diff])

      slope_raw, intercept, rval, pval, stderr = stats.linregress(Xi_arr, Vi_arr)
      hz_R2 = rval * rval # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
      hz = int(const.SIB_FREQ_ROUND_BASE * round(slope_raw / const.SIB_FREQ_ROUND_BASE)) # Kohno et al. Section 4.3

      return (hz, Xi_arr, Vi_arr, hz_R2, slope_raw)

    else:

      Xi_arr = numpy.zeros(nr_timestamps - 1)
      Vi_arr = numpy.zeros(nr_timestamps - 1)

      adjustment_recv = 0
      adjustment_tcp = 0
      for i in range(1, nr_timestamps):

        # in doubt, also do this for packet receive timestamps
        if recv_ts[i] + const.SIB_TS_OVERFLOW_THRESHOLD < recv_ts[i - 1]:
          if recv_ts[i - 1] > 2**31:
            adjustment_recv = 2**32
        xi = recv_ts[i] + adjustment_recv - offset_recv

        if tcp_ts[i] + const.SIB_TS_OVERFLOW_THRESHOLD < tcp_ts[i - 1]:
          if tcp_ts[i - 1] > 2**31:
            adjustment_tcp = 2**32
        vi = tcp_ts[i] + adjustment_tcp - offset_tcp

        Xi_arr[i - 1] = xi
        Vi_arr[i - 1] = vi

      # We remove duplicates at low runtime because they may influence the rval**2
      # which in turn results in classification as incorrect clock rate
      # This does not touch the required monotonocity -> rval**2 will be very low
      # if timestamps are randomized
      ##########################################################################
      # https://stackoverflow.com/a/10996196
      diff = numpy.diff(Vi_arr)
      indices = []
      for i, val in enumerate(diff):
        if val == 0:
          indices.append(i)

      # if len(indices) >= int(len(Vi_arr) * const.SIB_TS_MONOTONICITY_PERCENTAGE):
      #   log.error('IPv{0} error: more than {1}% of timestamps to be removed for strict monotonicity!'.format(ipversion, int(const.SIB_TS_MONOTONICITY_PERCENTAGE * 100)))
      #   return (None, None, None, None, None)

      Xi_arr = numpy.delete(Xi_arr, indices) # remove duplicate timestamps
      Vi_arr = numpy.delete(Vi_arr, indices) # -> few timestamps should not have duplicates

      if len(Vi_arr) > 1:
        pass # We do not check for monotonicity -> check rval**2 instead (few timestamps )
        # numpy.all(numpy.diff(Vi_arr) >= 0) # probably more elegant way but returns new array with diffs (slicing only uses array views (twice as fast!))
        # if not numpy.all(Vi_arr[1:] >= Vi_arr[:-1]): # non-monotonic after adjustment -> probably randomized timestamps
        #   return (None, None, None, None, None)
      elif len(Vi_arr) > 0:
        tcp_diff = tcp_ts[0] - offset_tcp
        if tcp_diff == 0:
          log.error('IPv{0}: only identical remote timestamps after removing duplicates available, linregress not possible for {1} / {2}'.format(ipversion, self.ip4, self.ip6))
          return (None, None, None, None, None)

        # do linreg with offset value and the only timestamp in the array
        Xi_arr = numpy.array([0, recv_ts[0] - offset_recv])
        Vi_arr = numpy.array([0, tcp_diff])
      elif len(Vi_arr) <= 0: # should probably never happen
        log.error('IPv{0}: not enough timestamps available after removing duplicates - {1} / {2}'.format(ipversion, self.ip4, self.ip6))
        return (None, None, None, None, None)


      # perform regression
      slope_raw, intercept, rval, pval, stderr = stats.linregress(Xi_arr, Vi_arr)
      hz_R2 = rval * rval # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
      hz = int(const.SIB_FREQ_ROUND_BASE * round(slope_raw / const.SIB_FREQ_ROUND_BASE)) # Kohno et al. Section 4.3

      return (hz, Xi_arr, Vi_arr, hz_R2, slope_raw)


  def calc_frequency(self):
    hz4, Xi4, Vi4, hz4_R2, hz4_raw = self._calc_frequency(ipversion = 4)
    hz6, Xi6, Vi6, hz6_R2, hz6_raw = self._calc_frequency(ipversion = 6)

    # DO NOT DECIDE HERE -> just plain calculations
    # if abs(hz4_raw) < const.SIB_FREQ_IP4_MIN and abs(hz6_raw) < const.SIB_FREQ_IP6_MIN:
    #   self.sibling_status = const.SIB_STATUS_ALL_FREQ_TOO_LOW
    #   log.error('Both IPs frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
    #   return False
    # if abs(hz4_raw) < const.SIB_FREQ_IP4_MIN:
    #   self.sibling_status = const.SIB_STATUS_IP4_FREQ_TOO_LOW
    #   log.error('IPv4 - frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
    #   return False
    # if abs(hz6_raw) < const.SIB_FREQ_IP6_MIN:
    #   self.sibling_status = const.SIB_STATUS_IP6_FREQ_TOO_LOW
    #   log.error('IPv6 - frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
    #   return False
    #
    # if hz4_R2 < const.SIB_FREQ_IP4_R2_MIN_LOWRT and hz6_R2 < const.SIB_FREQ_IP6_R2_MIN_LOWRT:
    #   self.sibling_status = const.SIB_STATUS_ALL_R2_TOO_LOW
    #   log.error('Both IPs r-squared below defined threshold - maybe randomized TS ({0} / {1}): {2} / {3}'.format(hz4_R2, hz6_R2, self.ip4, self.ip6))
    #   return False
    # if hz4_R2 < const.SIB_FREQ_IP4_R2_MIN_LOWRT:
    #   self.sibling_status = const.SIB_STATUS_IP4_R2_TOO_LOW
    #   log.error('IPv4 - r-squared below defined threshold (< {0}) - maybe randomized TS: {1} / {2}'.format(const.SIB_FREQ_IP4_R2_MIN, self.ip4, self.ip6))
    #   return False
    # if hz6_R2 < const.SIB_FREQ_IP6_R2_MIN_LOWRT:
    #   self.sibling_status = const.SIB_STATUS_IP6_R2_TOO_LOW
    #   log.error('IPv6 - r-squared below defined threshold (< {0}) - maybe randomized TS: {1} / {2}'.format(const.SIB_FREQ_IP6_R2_MIN, self.ip4, self.ip6))
    #   return False


    self.hz4, self.Xi4, self.Vi4, self.hz4_R2, self.hz4_raw = hz4, Xi4, Vi4, hz4_R2, hz4_raw
    self.hz6, self.Xi6, self.Vi6, self.hz6_R2, self.hz6_raw = hz6, Xi6, Vi6, hz6_R2, hz6_raw
    self.hz_diff = abs(hz4_raw - hz6_raw)
    self.hz_rsqrdiff = abs(self.hz4_R2 - self.hz6_R2)

    return True


  def _calc_outlier_removal(self, ipversion):
    # remove outliers off the confidence level
    if ipversion == 4:
      offsets = self.tcp_ts_offsets4
    elif ipversion == 6:
      offsets = self.tcp_ts_offsets6

    y_vals = [ y for x, y in offsets ]

    with numpy.errstate(invalid = 'raise'):
      try:
        mean = numpy.mean(y_vals)
        stddev = numpy.std(y_vals) # may raise numpy warning for malformed array
      except Exception as e:
        log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))

    lower, upper = (mean - const.SIB_Z_SCORE_CONFIDENCE_LEVEL_97 * stddev, mean + const.SIB_Z_SCORE_CONFIDENCE_LEVEL_97 * stddev)
    cleaned_arr = []

    for value_pair in offsets: # list of tuples
      if value_pair[1] < lower or value_pair[1] > upper:
        continue
      cleaned_arr.append(value_pair)

    return cleaned_arr

  def _calc_dynamic_range(self, ipversion = None):
    # we do not prune the array in low runtime setting
    if ipversion == 4:
      offset_arr = self.cleaned_mean4_sigma
    elif ipversion == 6:
      offset_arr = self.cleaned_mean6_sigma
    else:
      log.error('Invalid ipversion provided')
      return None

    try:
      offsets = sorted([ y for _, y in offset_arr ])
      length = len(offsets)
      # lower_index = int(round((const.SIB_DYNRNG_LOWER_CUT_PERCENT * length) / 100))
      # upper_index = int(round((const.SIB_DYNRNG_UPPER_CUT_PERCENT * length) / 100))

      low_val = offsets[0] # lower_index
      high_val = offsets[length - 1] # upper_index - 1
      range = high_val - low_val
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return None

    return range


  #### SPLINE calculations
  ##############################################################################
  def _calc_equal_bin_size(self, offsets, nr_bins):
    start = offsets[0][0] # list(tuple(x, y))
    stop = offsets[-1][0]
    return round((stop - start) / nr_bins, 1)

  def _calc_spline(self, bin_size, packed_arr):
    try:
      x, y = zip(*packed_arr)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return None

    spline_spacing = self.number_of_timestamps # int(self.number_of_timestamps / bin_size)
    xs = numpy.arange(x[0], x[-1], spline_spacing)

    nr_bins = int(self.number_of_timestamps / 2) # safety first
    knots = [ x[0] + i * bin_size for i in range(1, nr_bins) ]

    try:
      # according to scipy docs removing first and last knot
      # https://docs.scipy.org/doc/scipy/reference/generated/scipy.interpolate.LSQUnivariateSpline.html
      #knots = interpolate.UnivariateSpline(x, y).get_knots()
      spl = interpolate.LSQUnivariateSpline(x, y, knots[1:-1], w = None, bbox = [None, None], k = const.SIB_SPLINE_DEGREE)
      curve = spl(xs)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return None

    return (curve, xs)

  def calc_spline(self):
    nr_bins = self.number_of_timestamps - 2
    try:
      bin_size4 = self._calc_equal_bin_size(self.cleaned_mean4_sigma, nr_bins)
      bin_size6 = self._calc_equal_bin_size(self.cleaned_mean6_sigma, nr_bins)
    except Exception as e:
      log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4 = self.ip4, ip6 = self.ip6))
      return False

    if not bin_size4 or not bin_size6:
      return False

    self.bin_size4, self.bin_size6 = bin_size4, bin_size6

    # eliminate first and last points for spline computation
    packed4 = self.cleaned_mean4_sigma[1 : -1]
    packed6 = self.cleaned_mean6_sigma[1 : -1]

    res4 = self._calc_spline(self.bin_size4, packed4)
    res6 = self._calc_spline(self.bin_size6, packed6)

    if not res4 or not res6:
      return False

    self.spline_arr4, self.xs4 = res4
    self.spline_arr6, self.xs6 = res6
    return True
  ##############################################################################


  def evaluate(self):
    if self.calc_finished:
      log.warning('Already evaluated SiblingCandidate (result: {0}) {1} / {2} -> {3}'.format(self.is_sibling, self.ip4, self.ip6, self.sibling_status))
      return self.is_sibling

    # check ssh keys
    self.ssh_keys_match = self.keys_match()
    self.ssh_agents_match = self.agents_match()

    try:

      if not self.calc_frequency():
        raise SiblingEvaluationError()

      if not self.calc_raw_tcp_timestamp_value():
        log.error('Raw TCP timestamp difference calculation error')
        raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_RAW_TS_DISTANCE_ERROR)

      # DO NOT DECIDE HERE => ML should do this!
      # check v4/v6 frequencies and r-squared match
      # if self.hz_diff > const.SIB_FREQ_HZ_DIFF_MAX_LOWRT or self.hz_rsqrdiff > const.SIB_FREQ_R2_DIFF_MAX_LOWRT:
      #   log.error('Frequency difference too high')
      #   raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_FREQ_DIFF_TOO_HIGH)


      if const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES and self.number_of_timestamps >= const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES_MIN_TIMESTAMPS:
        # Calculations work for two timestamps including dynamic range
        if not self.calc_time_offsets():
          log.error('Time offsets calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_ALL_OFFSET_ARRAY_ERROR)

        if not self.calc_outlier_removal():
          log.error('Outlier calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_MEAN_REMOVAL_ERROR)

        if not self.calc_pairwise_point_distance():
          log.error('Pairwise point distance calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_PPD_ERROR)

        if not self.calc_ppd_mean_median_thresholds():
          log.error('PPD mean/median threshold calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_PPD_THRESHOLD_ERROR)

        if not self.calc_sigma_outlier_removal():
          log.error('Two sigma outlier removal calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_SIGMA_OUTLIER_REMOVAL_ERROR)

        if not self.calc_dynamic_range():
          log.error('Dynamic range calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_DYNAMIC_RANGE_ERROR)


        if not self.calc_alpha(): # skew angle
          log.error('Angle alpha calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_ALPHA_ERROR)

        if not self.calc_theta(): # Beverly Section 3.3; the angle between the lines built by drawing alpha4/alpha6
          log.error('Theta calculation error') # if theta < tau (threshold value = 1.0) then inferred to be siblings
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_THETA_ERROR)


        ##########################################################################

      if const.SIB_LOWRT_CALC_SPLINE and self.number_of_timestamps >= const.SIB_LOWRT_MIN_TIMESTAMPS_FULL_CALC:
        # We limit the number of timestamps to at least x to get useful results for spline calculations
        if not self.calc_spline():
          log.error('Spline calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_SPLINE_CALC_ERROR)

        if not self.calc_curve_mapping():
          log.error('Curve mapping calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_CURVE_MAPPING_ERROR)

        if not self.calc_curve_diff_percent():
          log.error('Curve percentage mapping calculation error')
          raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_CURVE_PERCENT_MAPPING_ERROR)


      self.calc_finished = True

    except SiblingEvaluationError as e:
      self.calc_finished = True
      self.calc_error = True
      if e.sibling_status is not None:
        self.sibling_status = e.sibling_status
    finally:
      # always check if we can determine sibling status based on raw ts val diff
      raw_ts_diff = getattr(self, 'raw_timestamp_diff', None)

      # TODO: ask ml model or other algorithms for sibling decision

      if raw_ts_diff and raw_ts_diff <= LowRTSiblingCandidate.TS_DIFF_THRESHOLD: # sibling based on raw ts val diff
        if self.calc_error: # if calc_error occurred we append the status message
          self.sibling_status = '{0},{1}'.format(self.sibling_status, const.SIB_STATUS_IS_SIBLING_RAW_TS_VAL_DIFF)
        else:
          self.sibling_status = const.SIB_STATUS_IS_SIBLING_RAW_TS_VAL_DIFF
        self.is_sibling = True
        return True
      else:
        # no sibling
        if self.calc_error: # if calc_error occurred we append the status message
          self.sibling_status = '{0},{1}'.format(self.sibling_status, const.SIB_STATUS_IS_NO_SIBLING)
        else:
          self.sibling_status = const.SIB_STATUS_IS_NO_SIBLING
        self.is_sibling = False
        return False


################################################################################
################################################################################
################################################################################
################################################################################

class SiblingResult(object):
  """
  This class is intended to store calculated results and other class members.
  """
  def __init__(self, ip4, ip6, port4, port6, tcpopts4, tcpopts6, sibcand_result_dict = None, domains = None, ssh_available = None, ssh_keys = None, trace_set_id = None):
    """
    If sibcand_result_dict is None, the results must be loaded from the accompanying results file.
    """
    self.ip4 = ip4
    self.ip6 = ip6
    self.port4 = port4
    self.port6 = port6
    self.tcpopts4 = tcpopts4
    self.tcpopts6 = tcpopts6
    self.results = sibcand_result_dict
    self.domains = domains
    self.ssh_available = ssh_available
    self.ssh_keys = ssh_keys
    self.trace_set_id = trace_set_id

    if self.ip4 and self.ip6 and self.port4 and self.port6:
      str_to_hash = '{0}_{1}_{2}_{3}'.format(self.ip4, self.port4, self.ip6, self.port6)
      h = hashlib.md5()
      h.update(str_to_hash.encode('utf-8'))
      self.id = h.hexdigest()
    else:
      self.id = None


  def __getstate__(self):
    # modify __dict__ before pickling
    # we do not want to have self.results pickled because file size may increase heavily
    state = self.__dict__.copy()
    del state['results']
    return state

  def __setstate__(self, state):
    self.__dict__.update(state)


  @property
  def X(self):
    return self.results


  # @property
  # def X(self):
  #   return pandas.DataFrame(self.results)
  #
  #
  # def predict(self, model, keys = None):
  #   if not keys:
  #     keys = [ 'raw_timestamp_diff' ]
  #
  #   X = self.X.filter(items = keys, axis = 'columns')
  #
  #   self.predicted_proba = model.predict_proba(X)
  #   self.predicted = model.predict(X)
  #
  #   return (self.predicted, self.predicted_proba)


  def append_data(self, outfile, keys, delimiter = ';', newline = True):
    outlist = [ self.id ]
    for key in keys:
      try:
        outlist.append(str(self.results[key]))
      except KeyError:
        outlist.append('')

    outfile.write(delimiter.join(outlist))
    if newline:
      outfile.write('\n')

    self.resultfile = pathlib.Path(outfile.name).name # keep filename
