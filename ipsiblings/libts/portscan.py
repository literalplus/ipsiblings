# libts/tpportscan.py
#
# (c) 2018 Marco Starke
#


import multiprocessing
import queue  # only exceptions
import random
import select

import scapy.all as scapy

from .. import libconstants as const
from .. import liblog
from .. import libtools

log = liblog.get_root_logger()


class TSPortScan(object):
    """
    Base class - TraceSetPortScan / CandidatePortScan

    Override process_record function.
    """

    def __init__(
            self, nodes4, nodes6, *args, port_list=[x for x in range(const.PORT_MAX)], iface='en0',
            dump_unknown_packets=False, **kwargs
    ):
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
        self.v4sending_finished = self.mp_manager.Value('B', 0)  # unsigned char
        self.v6sending_finished = self.mp_manager.Value('B', 0)
        self.total_records = self.mp_manager.Value('I', 0)  # unsigned int

        self.packet_filter = 'tcp and (dst port {0} or dst port {1} or dst port {2})'.format(const.STOP_PORT,
                                                                                             const.V4_PORT,
                                                                                             const.V6_PORT)

        self.v4pkt = scapy.Ether() / scapy.IP() / scapy.TCP(
            sport=const.V4_PORT, flags='S',
            options=[('Timestamp', (const.TS_INITIAL_VAL, 0)), ('WScale', 0)]
        )  # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)
        self.v6pkt = scapy.Ether() / scapy.IPv6() / scapy.TCP(
            sport=const.V6_PORT, flags='S',
            options=[('Timestamp', (const.TS_INITIAL_VAL, 0)), ('WScale', 0)]
        )  # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)

    def process_record(self, record, *args, **kwargs):
        raise NotImplementedError()

    def _send4(self):
        socket4 = scapy.conf.L2socket(iface=self.iface)
        pkt = self.v4pkt.copy()
        for port in random.sample(self.portlist, k=self.portlist_length):
            pkt.payload.payload.dport = port
            for ip in random.sample(self.nodes4, k=self.nodes4_length):
                pkt.payload.dst = ip
                socket4.send(pkt)
        socket4.close()
        log.debug('Sending IPv4 packets finished, sent {0} packets'.format(self.nr_v4packets))
        self.v4sending_finished.value = 1

    def _send6(self):
        socket6 = scapy.conf.L2socket(iface=self.iface)
        pkt = self.v6pkt.copy()
        for port in random.sample(self.portlist, k=self.portlist_length):
            pkt.payload.payload.dport = port
            for ip in random.sample(self.nodes6, k=self.nodes6_length):
                pkt.payload.dst = ip
                socket6.send(pkt)
        socket6.close()
        log.debug('Sending IPv6 packets finished, sent {0} packets'.format(self.nr_v6packets))
        self.v6sending_finished.value = 1

    def _sniff(self):
        # https://github.com/secdev/scapy/issues/989 - own sniff implementation
        sock = scapy.conf.L2listen(iface=self.iface, type=scapy.ETH_P_ALL, filter=self.packet_filter)

        while True:
            try:  # prevent sniff process to terminate on error (excludes KeyboardInterrupt and SystemExit)
                rlist = select.select([sock], [], [])
                if rlist:
                    p = sock.recv()  # returns exactly one packet -> socket.AF_PACKET
                    if p[scapy.TCP].dport == const.STOP_PORT:  # STOP packet handling
                        if scapy.Raw in p and p[scapy.Raw].load.decode('utf-8') == self.stop_packet_load:
                            # only break if we received the stop packet which matches the current instance
                            log.debug('Received STOP packet [{0}] ...'.format(self.stop_packet_load))
                            break
                    ts = libtools.get_ts(p)  # only packets with timestamp option set
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
        p4 = scapy.Ether() / scapy.IP(dst='127.0.0.1')\
             / scapy.TCP(dport=const.STOP_PORT) / scapy.Raw(load=self.stop_packet_load)
        p6 = scapy.Ether() / scapy.IPv6(dst='::1')\
             / scapy.TCP(dport=const.STOP_PORT) / scapy.Raw(load=self.stop_packet_load)
        scapy.sendp([p4, p6], verbose=0)

    def start(self):
        """
        Start timestamp port query for given IPs.
        """
        self.sniff_proc = multiprocessing.Process(name='sniff', target=self._sniff)
        v4proc = multiprocessing.Process(name='v4send', target=self._send4)
        v6proc = multiprocessing.Process(name='v6send', target=self._send6)

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

    def wait(self, timeout=1):
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

    def process_results(self, *args, timeout=1, **kwargs):
        if not timeout:
            timeout = 1

        nr_records = 0

        while True:
            try:
                record = self.response_queue.get(timeout=timeout)
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


class TraceSetPortScan(TSPortScan):

    def __init__(self, nodes4, nodes6, port_list=[x for x in range(const.PORT_MAX)], iface='en0'):
        super().__init__(nodes4, nodes6, port_list=port_list, iface=iface)
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
                self.v4results[ip] = {port: [(remote_ts, received_ts, p)]}
        elif ipversion == const.IP6:
            if ip in self.v6results:
                if port in self.v6results[ip]:
                    self.v6results[ip][port].append((remote_ts, received_ts, p))
                else:
                    self.v6results[ip][port] = [(remote_ts, received_ts, p)]
            else:
                self.v6results[ip] = {port: [(remote_ts, received_ts, p)]}
        else:
            return False  # should never reach here

        return True

    def results(self):
        return self.v4results, self.v6results


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
