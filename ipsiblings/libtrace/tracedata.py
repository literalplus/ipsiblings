# libtrace/tracedata.py
#
# (c) 2018 Marco Starke
#
import csv

from .. import liblog
from .. import libtools

log = liblog.get_root_logger()


class TraceData(object):
    """
    Holds the collected timestamps of all responding IP/Port combinations of Traces.

    data => { 4: { IPv4: { port: [timestamps] } }, 6: { IPv6: { port: [timestamps] } } }
    tcp_options => { IP: scapy.TCP_options }
    """

    def __init__(self):
        self.trace_data = {4: {}, 6: {}}
        self.tcp_options = {}

    def data(self):
        return self.trace_data

    def tcpoptions(self):
        return self.tcp_options

    def has_timestamp_data(self):
        return self.trace_data[4] and self.trace_data[6]

    def add_record(self, ip, port, timestamps=None, tcp_options=None, ipversion=None):
        """
        Add a single record.

        timestamps -> [(remote_ts, received_ts)]
        tcp_options -> TCP options as provided by scapy
        """
        if timestamps is None:
            timestamps = []
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
            data[ip] = {port: timestamps}

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

    def from_file(self, filename, delimiter=','):

        with open(filename, mode="r", newline='') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=delimiter)

            data = self.trace_data[4]  # start with ip4 data

            # use simple state machine
            # 0: read IP, 1: read port and timestamps
            state = 0  # start with reading IP address
            current_ip = None

            for row in csvreader:
                if not row:  # go on with next IP address
                    state = 0
                    continue

                if row[0].startswith('='):  # switch to IPv6 timestamps
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
                    remote_ts = [int(x) for x in row[1::2]]
                    received_ts = [float(x) for x in row[2::2]]
                    timestamps = zip(remote_ts, received_ts)
                    data[current_ip][port] = list(timestamps)  # generator to list
                    # stay in state 1 until empty row reached
                    continue

    def to_file(self, filename, delimiter=','):
        if not self.trace_data[4] and not self.trace_data[6]:
            # if no data is available do not create a file at all
            return None

        with open(filename, mode="w") as outfile:
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
                        outfile.write(delimiter.join(str(ts) for ts_tuple in timestamps for ts in
                                                     ts_tuple))  # join the list of tuples into one string
                        outfile.write('\n')

                    outfile.write('\n')

    def from_file_tcp_options(self, filename, delimiter=','):
        # row = [ip, opt1:val1, opt2:val2, opt3:val3.1:val3.2, opt4:val4]
        with open(filename, mode="r", newline='') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=delimiter)

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

    def to_file_tcp_options(self, filename, delimiter=','):
        if not self.tcp_options:
            return None

        with open(filename, mode="w") as outfile:

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
