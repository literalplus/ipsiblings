# libts/serialization.py
#
# (c) 2018 Marco Starke
#


import contextlib
import csv
import ipaddress
import os

from .candidatepair import CandidatePair
from .. import libconstants as const
from .. import liblog
from .. import libtools

log = liblog.get_root_logger()


def load_candidate_pairs(candidate_file, ts_data_file=None, delimiter=';', port_delimiter=',', v4bl_re=None,
                         v6bl_re=None, include_domain=False):
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
        with open(tcpopts_file, mode="r", newline='') as csvfile:
            csvreader = csv.reader(csvfile, delimiter=port_delimiter)  # use ',' here
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
                    if values and libtools.is_iterable(values):  # safety first
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
        with open(ts_data_filename, mode="r") as tsdatafile:
            reader = csv.reader(tsdatafile, delimiter=',')  # constant delimiter here

            data = ts_data4
            # 0: read IP, 1: read port and timestamps
            state = 0  # start with reading IP address
            current_ip = None

            for row in reader:
                if not row:  # go on with next IP address
                    state = 0
                    continue

                if row[0].startswith('='):  # switch to IPv6 timestamps
                    data = ts_data6
                    state = 0
                    continue

                if state == 0:
                    current_ip = row[0]
                    data[current_ip] = {}
                    state = 1
                    continue

                if state == 1:  # port, tcp_ts, recv_ts, tcp_ts, recv_ts, ...
                    port = int(row[0])
                    remote_ts = [int(x) for x in row[1::2]]  # slice all odd (starts at index 1)
                    received_ts = [float(x) for x in row[2::2]]  # slice all even (starts at index 2)
                    timestamps = zip(remote_ts, received_ts)  # build tuples (tcp_ts, recv_ts)
                    data[current_ip][port] = list(timestamps)  # generator to list
                    # stay in state 1 until empty row reached
                    continue

    if not ts_data4 or not ts_data6:
        ts_data_available = False
    else:
        ts_data_available = True

    candidate_pairs = {}

    with open(candidate_file, newline='', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=delimiter)

        # determine csv structure according to function description
        header = next(csvreader)
        row_length = len(header) if include_domain else len(header) - 1  # domain always on last position

        row_func = None  # will never be used

        if row_length == 2:
            row_func = lambda row: (
                str(ipaddress.ip_address(row[0])), None, str(ipaddress.ip_address(row[1])), None, [])
            ports_available = False
        elif row_length == 3:
            row_func = lambda row: (str(ipaddress.ip_address(row[0])), None, str(ipaddress.ip_address(row[1])), None,
                                    row[2].split(port_delimiter) if len(row) == 3 else [])
            ports_available = False
        elif row_length == 4:
            row_func = lambda row: (str(ipaddress.ip_address(row[0])), [int(p) for p in row[1].split(port_delimiter)],
                                    str(ipaddress.ip_address(row[2])), [int(p) for p in row[3].split(port_delimiter)],
                                    [])
            ports_available = True
        elif row_length == 5:
            row_func = lambda row: (str(ipaddress.ip_address(row[0])), [int(p) for p in row[1].split(port_delimiter)],
                                    str(ipaddress.ip_address(row[2])), [int(p) for p in row[3].split(port_delimiter)],
                                    row[4].split(port_delimiter) if len(row) == 5 else [])
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
            cp = CandidatePair(ip4, ip6, ports4=ports4, ports6=ports6, tcp4_opts=tcp4_opts, tcp6_opts=tcp6_opts,
                               ip4_ts=ip4_ts, ip6_ts=ip6_ts, domains=domains)
            candidate_pairs[(ip4, ip6)] = cp

    return ports_available, ts_data_available, tcpopts_available, candidate_pairs


def write_candidate_pairs(
        candidate_pairs, base_directory, delimiter=';', port_delimiter=',', only_active_nodes=True,
        write_candidates=True, write_ts_data=True, write_tcp_opts_data=True, include_domain=True
):
    """
    Writes candidate pairs to base_directory/CANDIDATE_PAIRS_FILE_NAME and timestamp data,
    if available and desired, to base_directory/CANDIDATE_PAIRS_DATA_FILE_NAME.

    Return (candidate_lines_written, data_lines_written)
    """
    if not candidate_pairs:
        log.warning('No candidate pairs to write!')
        return 0, 0

    if delimiter == port_delimiter:
        raise ValueError('Row delimiter and Port delimiter must not be the same character!')

    dir_status = libtools.create_directories(base_directory)
    if dir_status:
        log.info('Successfully created base directory [{0}]'.format(base_directory))
    elif dir_status is None:
        pass  # do not issue a warning if already existing at this point
    else:
        log.error('Error while creating base directory [{0}] - Aborting ...'.format(base_directory))
        return 0, 0

    cp_line_counter = 0
    data_line_counter = 0

    if write_candidates:
        longest_row = 0  # determine which header to use (domain may not be available on first entries)
        row_list = []

        for cp in candidate_pairs.values():
            if only_active_nodes and not cp.is_active():
                continue

            item_list = []
            item_list.append(cp.ip4)
            if cp.ports4:
                item_list.append(port_delimiter.join([str(p) for p in sorted(cp.ports4)]))
            item_list.append(cp.ip6)
            if cp.ports6:
                item_list.append(port_delimiter.join([str(p) for p in sorted(cp.ports6)]))
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

            with open(filename, mode="w") as outfile:
                outfile.write('{0}\n'.format(header))

                for row in row_list:
                    outfile.write('{0}\n'.format(row))
                    cp_line_counter = cp_line_counter + 1

            log.info('Candidate pairs written: {0} [{1}]'.format(cp_line_counter, str(filename)))
        else:
            log.warning('No active CandidatePairs available to write!')
            if not write_ts_data and not write_tcp_opts_data:  # only return if nothing else to do
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
                    write_cache4.append(port_delimiter)  # use ',' here
                    write_cache4.append(port_delimiter.join(str(ts) for ts_tuple in timestamps for ts in
                                                            ts_tuple))  # join the list of tuples into one string
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

        if write_cache4 or write_cache6:  # only write file if any timestamps available
            with open(filename, mode="w") as outfile:
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
        with open(filename, mode="w") as outfile:
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
                outfile.write('{0}\n'.format(','.join(outstring4)))  # constant delimiter here

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
                outfile.write('{0}\n'.format(','.join(outstring6)))  # constant delimiter here

        if line_counter > 0:
            log.debug('Finished writing TCP options to [{0}]'.format(filename))
        else:  # remove the file if nothing was written
            with contextlib.suppress(FileNotFoundError):
                os.remove(filename)

    return cp_line_counter, data_line_counter
