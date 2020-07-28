# libtrace/trace.py
#
# (c) 2018 Marco Starke
#

import csv
import hashlib
import itertools

import scapy.all as scapy
from prettytable import PrettyTable

from .. import libconstants as const
from .. import liblog
from .. import libtools

log = liblog.get_root_logger()


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
        table = PrettyTable(['Hop', 'IPv4 Trace', 'IPv6 Trace'])

        if self.iface:
            str_lst.append(
                "{0} / {1}\n==>>\n{2} / {3} {name}\n\n".format(self.v4src, self.v6src, self.v4target, self.v6target,
                                                               name=domainstr))
            table.add_row((0, self.v4src, self.v6src))
            table.add_row(('--', '----', '----'))
        else:
            str_lst.append("==>>\n{0} / {1} {name}\n\n".format(self.v4target, self.v6target, name=domainstr))

        rows = itertools.zip_longest(self.v4trace, self.v6trace, fillvalue='')

        last_hop = 0
        for i, row in enumerate(rows, start=1):
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

        return v4nodes, v6nodes

    def init(self, v4target, v6target, v4trace, v6trace, domain=None, v4bl_re=None, v6bl_re=None, iface=None):
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

    def initfile(self, filename, delimiter=',', v4bl_re=None, v6bl_re=None, iface=None):
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

        with open(filename, mode="r", newline='') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=delimiter)

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

    def get_global_valid_IPs(self, apply_ignore_regex=False):
        """
        Uses libtools.get_global_ip_addresses() to return traces only containing global IPs from the object's traces.
        If blacklist regex patterns were submitted to the init() function, they can be applied by setting
        'apply_ignore_regex' to True.
        """
        if apply_ignore_regex:
            v4whitelist = {}
            v6whitelist = {}

            for ttl, ip in enumerate(self.v4trace, start=1):
                if not self.v4bl_re.match(ip):
                    v4whitelist[ttl] = ip

            for hlim, ip in enumerate(self.v6trace, start=1):
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

    def get_timestamps(self, trace_data_obj=None):
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
                v4packets[ip] = {port: pkt_data[0][2] for port, pkt_data in
                                 ts_results[0][ip].items()}  # index 2 -> scapy packet

        if ts_results[1]:
            for ip in ts_results[1]:
                v6nodes[ip] = list(ts_results[1][ip].keys())
                v6packets[ip] = {port: pkt_data[0][2] for port, pkt_data in ts_results[1][ip].items()}

        self.active_nodes4_length = len(v4nodes)
        self.active_nodes6_length = len(v6nodes)

        self.active_nodes = (v4nodes, v6nodes)
        self.active_nodes_packets = (v4packets, v6packets)

    def get_number_of_active_nodes(self):
        """
        Returns (nr of ip4 active nodes, nr of ip6 active nodes)
        """
        return self.active_nodes4_length, self.active_nodes6_length

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

    def from_file(self, name, delimiter=',', v4bl_re=None, v6bl_re=None, iface=None):
        return self.initfile(name, delimiter, v4bl_re, v6bl_re, iface)

    def to_file(self, name):
        with open(name, mode="w") as outfile:
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

    def active_nodes_from_file(self, name, pcap_name=None):
        """
        If pcap_name is None 'name' + '.pcap' is used as file name.
        """
        v4nodes = {}
        v6nodes = {}
        v4packets = {}
        v6packets = {}

        with open(name, mode="r", newline='') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=',')
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
        for p in packetlist:  # packets contain Ether() layer
            version = p.payload.version
            ip = p.payload.src
            port = p.payload.payload.sport
            if version == const.IP_VERSION_4:
                v4packets[ip] = {port: p}
            elif version == const.IP_VERSION_6:
                v6packets[ip] = {port: p}
            else:
                log.error('Unknown packet: {0}'.format(p))

        self.active_nodes_packets = (v4packets, v6packets)

    def active_nodes_to_file(self, name, pcap_name=None):
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
        with open(name, mode="w") as outfile:
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

        return v4len, v6len

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
