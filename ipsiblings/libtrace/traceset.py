# libtrace/traceset.py
#
# (c) 2018 Marco Starke
#


import glob
import hashlib
import os

from . import TraceData
from .trace import Trace
from .. import liblog
from .. import libtools
from ..libtools import NicInfo, NO_SKIPS, SkipList

log = liblog.get_root_logger()


class TraceSet(object):
    """
    Routes may differ for the same destination.
    Holds different Trace objects and the (only one) TraceData.

    Acts as a wrapper for the TraceData object.
    """

    def __init__(self, target=None, domain=None):
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
                raise ValueError(
                    'Missing IP version! Can not retrieve A or AAAA record for \'{0}\''.format(self.domain))

        if self.target:
            self.traceset_id = self._id()
            self.tcp_sequence = self._tcp_seq()
        else:
            self.traceset_id = None
            self.tcp_sequence = None

    def __str__(self):
        string_list = ['Trace Set ID: {0} - Traces: {1}'.format(self.traceset_id, str(len(self.traces)))]
        for id, trace in self.traces.items():
            string_list.append('Trace ID: {0}\n{1}'.format(id, str(trace)))

        return '\n\n'.join(string_list)

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
        return int(self.traceset_id[:8], 16)  # first 32bit

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
            return self.active_nodes4, self.active_nodes6

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

        return v4nodes, v6nodes

    def get_number_of_active_nodes(self):
        """
        Returns number of active nodes.
        Caches the result.
        -> ( #IPv4, #IPv6 )
        """
        if not self.number_active_nodes4 or not self.number_active_nodes6:
            self.get_active_nodes()  # cache the result to return # active nodes

        return self.number_active_nodes4, self.number_active_nodes6

    def add_trace(self, trace):
        if isinstance(trace, Trace):
            if trace.id() not in self.traces:
                self.traces[trace.id()] = trace
                return True
            else:
                return False
        log.debug('Argument is not a Trace object: {0}'.format(str(trace)))
        return False

    def add_record(self, ip, port, timestamps, tcp_options, ipversion=None):
        return self.trace_data.add_record(ip, port, timestamps, tcp_options=tcp_options, ipversion=ipversion)

    def add_records(self, records):
        return self.trace_data.add_records(records)

    def from_file(self, directory, nic: NicInfo, skip_list: SkipList = NO_SKIPS):
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

        trace_files = [fn for fn in glob.glob(os.path.join(directory, 'trace_*.txt')) if 'active_nodes' not in fn]
        trace_active_nodes_files = [fn for fn in glob.glob(os.path.join(directory, 'trace_*.txt')) if
                                    'active_nodes' in fn]

        # ensure that all active nodes get assigned to the correct trace
        trace_files.sort()
        trace_active_nodes_files.sort()

        # debug output
        # for tf, antf in zip(trace_files, trace_active_nodes_files):
        #   print(tf.split('/')[4], antf.split('/')[4]) # index is based on directory tree

        for tf, antf in zip(trace_files, trace_active_nodes_files):
            trace_obj = Trace().from_file(tf, nic, skip_list=skip_list)
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

    def to_file(self, base_directory, write_target=True, write_traces=True, write_trace_data=True):
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
        elif dir_status == False:  # only if OSError != errno.EEXist
            log.error('Error while creating directory [{0}] - Aborting ...'.format(directory))
            return

        if write_target:
            targetfile = os.path.join(directory, 'target.txt')
            with open(targetfile, mode="w") as outfile:
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
        self.to_file(base_directory, write_target=False, write_traces=False, write_trace_data=True)

    def has_timestamp_data(self):
        return self.trace_data.has_timestamp_data()

    def has_candidates(self):
        # a trace can have ip4 nodes but another trace can have ip6 nodes (same target!)
        has_ip4 = any([trace.has_ip4_candidates() for trace in self.traces.values()])
        has_ip6 = any([trace.has_ip6_candidates() for trace in self.traces.values()])

        if has_ip4 and has_ip6:
            return True

        return False
