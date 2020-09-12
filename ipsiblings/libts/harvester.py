# libts/harvester.py
#
# (c) 2018 Marco Starke
#
import abc
import multiprocessing
import queue  # only exceptions
import random
import select
import threading

import scapy.all as scapy

from .. import libconstants as const
from .. import liblog
from .. import libtools
from ..bootstrap import Wiring
from ..bootstrap.exception import ConfigurationException
from ..config.model import HarvesterConfig, AppConfig
from ..libtools import NicInfo
from ..preparation import PreparedTargets, PreparedPairs

log = liblog.get_root_logger()


class Harvester(metaclass=abc.ABCMeta):
    """
    Base class - TraceSetHarvester / CandidateHarvester

    Override __init__ and process_record functions.
    """

    def __init__(self, nic: NicInfo, conf: HarvesterConfig, *args, **kwargs):
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
        self.conf = conf
        self.nic = nic

        self.run_thread = None

        self.mp_manager = multiprocessing.Manager()

        self.runs_stop_event = self.mp_manager.Event()
        self.runs_stop_event.clear()
        self.stop_packet_load = 'STOP_{0}'.format(random.getrandbits(64))

        self.response_queue = self.mp_manager.Queue()

        # typecodes - https://docs.python.org/3.7/library/array.html
        self.stop_all = self.mp_manager.Value('B', 0)  # unsigned char
        self.runs_completed = self.mp_manager.Value('B', 0)

        self.nr_runs = self.mp_manager.Value('I', int(self.conf.runtime / self.conf.interval))  # unsigned int
        self.run_counter = self.mp_manager.Value('I', 1)
        self.total_records = self.mp_manager.Value('I', 0)

        self.packet_filter = '((tcp) and ((dst port {0}) or (dst port {1}) or (dst port {2})))'.format(const.V4_PORT,
                                                                                                       const.V6_PORT,
                                                                                                       const.STOP_PORT)

        self.v4pkt = scapy.Ether() / scapy.IP() / scapy.TCP(
            sport=const.V4_PORT, flags='S', options=[
                ('Timestamp', (const.TS_INITIAL_VAL, 0)),
                ('WScale', 0)
            ]
        )  # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)
        self.v6pkt = scapy.Ether() / scapy.IPv6() / scapy.TCP(
            sport=const.V6_PORT, flags='S', options=[
                ('Timestamp', (const.TS_INITIAL_VAL, 0)),
                ('WScale', 0)
            ]
        )  # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)

        # since each process only reads one variable, it should be sufficient to use simple lists
        self.v4packets = []
        self.v6packets = []

    @abc.abstractmethod
    def process_record(self, records):
        """
        Handles the assignment of records received to the corresponding objects.
        """
        raise NotImplementedError

    def _send4(self):
        socket4 = scapy.conf.L2socket(iface=self.nic.name)
        for pkt in random.sample(self.v4packets, k=self.v4packets_length):
            if self.stop_all.value == 1:
                log.debug('Stopping IPv4 sending process ...')
                break
            socket4.send(pkt)
        socket4.close()

    def _send6(self):
        socket6 = scapy.conf.L2socket(iface=self.nic.name)
        for pkt in random.sample(self.v6packets, k=self.v6packets_length):
            if self.stop_all.value == 1:
                log.debug('Stopping IPv6 sending process ...')
                break
            socket6.send(pkt)
        socket6.close()

    def _sniff(self):
        # https://github.com/secdev/scapy/issues/989 - own sniff implementation

        # from that issue, might be interesting to change to AsyncSniffer: https://github.com/secdev/scapy/pull/1999

        sock = scapy.conf.L2listen(filter=self.packet_filter)

        while True:
            try:  # prevent sniff process to terminate on error (excludes KeyboardInterrupt and SystemExit)
                rlist = select.select([sock], [], [])
                if rlist:
                    p = sock.recv()
                    # STOP packet handling
                    if p[scapy.TCP].dport == const.STOP_PORT:
                        if scapy.Raw in p and p[scapy.Raw].load.decode('utf-8') == self.stop_packet_load:
                            # only break if we received the stop packet which matches the current instance
                            log.debug('Received STOP packet [{0}] ...'.format(self.stop_packet_load))
                            break
                    ts_tuple = libtools.get_ts(p)  # (TSval, TSecr)
                    if ts_tuple:
                        remote_ts = ts_tuple[0]  # TSval
                    else:
                        continue  # if no timestamp available ignore packet

                    # (tcp_seq, node_ip, remote_port, remote_ts, received_ts, tcp_options, ip_version)
                    record = (
                        p.payload.payload.ack - 1,
                        p.payload.src,
                        p.payload.payload.sport,
                        remote_ts,
                        p.time,
                        p[scapy.TCP].options,
                        p.payload.version
                    )
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
        self.send4 = multiprocessing.Process(target=self._send4, name='({0}) send4'.format(self.run_counter.value))
        self.send6 = multiprocessing.Process(target=self._send6, name='({0}) send6'.format(self.run_counter.value))

        self.send4.start()
        self.send6.start()

    def _start(self):
        """
        Repeat the _run function call at each interval until the runs_stop_event is set or the requested number of runs is reached
        """
        while True:
            log.info('Started run {0}'.format(self.run_counter.value))

            self.run_thread = threading.Thread(target=self._run)
            self.run_thread.start()

            if self.run_counter.value >= self.nr_runs.value:
                self.run_thread.join(1)  # give the run_thread some time to create the sending processes
                # block until BOTH sending processes finish their current run
                self.send4.join()
                self.send6.join()
                self.runs_completed.value = 1
                break

            self.run_counter.value = self.run_counter.value + 1

            # control the timing
            # blocks until interval passed (return False) or event is set (return True)
            if self.runs_stop_event.wait(timeout=self.conf.interval):
                break

    def start(self):
        """
        Returns the thread handle for the control thread which calls the _run function each defined interval.
        Starts the sniffing process.
        """
        self.sniff_proc = multiprocessing.Process(target=self._sniff, name='sniff')
        self.sniff_proc.start()
        # allow enough time to setup sniffing process
        self.sniff_proc.join(const.START_SNIFF_PROCESS_DELAY)

        t = threading.Thread(target=self._start)
        t.start()
        return t

    def _stop_sniff(self):
        # send STOP packet to localhost - to be sure do this for IPv4 and IPv6
        p4 = scapy.Ether() / scapy.IP(dst='127.0.0.1') / scapy.TCP(
            dport=const.STOP_PORT
        ) / scapy.Raw(load=self.stop_packet_load)
        p6 = scapy.Ether() / scapy.IPv6(dst='::1') / scapy.TCP(
            dport=const.STOP_PORT
        ) / scapy.Raw(load=self.stop_packet_load)
        scapy.sendp(p4, verbose=0)
        scapy.sendp(p6, verbose=0)

    def stop(self):
        log.debug('Stop requested ...')
        self.stop_all.value = 1
        self.runs_stop_event.set()

        self._stop_sniff()

        if self.runs_completed.value != 1:  # only necessary if runs are not already completed
            if self.run_thread:
                log.debug(
                    'Waiting for _run thread to finish '
                    '(this may take some time depending on number of packets to process) ...'
                )
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

    def process_results_running(self):
        return self._process_results(self.conf.running_timeout)

    def process_results_final(self):
        return self._process_results(self.conf.final_timeout)

    def _process_results(self, timeout):
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
                record = self.response_queue.get(timeout=timeout)
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


class CandidateHarvester(Harvester):
    def __init__(self, nic: NicInfo, prepared_pairs: PreparedPairs, conf: AppConfig):
        if not prepared_pairs.candidate_pairs:
            raise ValueError('Candidate pairs empty!')
        super().__init__(nic, conf.harvester)
        self.base_dir = conf.base_dir

        self.prepared_pairs = prepared_pairs

        self.cp_lut = {}

        for cp in self.prepared_pairs.get_models().values():
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

        log.info(
            f'Constructed packets to be sent each run: '
            f'{self.v4packets_length} v4 packets / '
            f'{self.v6packets_length} v6 packets / '
            f'{self.v4packets_length + self.v6packets_length} combined'
        )

    def process_record(self, record):
        tcp_seq, ip, port, remote_ts, received_ts, tcp_options, ipversion = record

        cp = self.cp_lut[ip]
        cp.add_ts_record(ip, port, remote_ts, received_ts, tcp_options, ipversion)


def provide_harvester_for(wiring: Wiring, prepared_targets: PreparedTargets) -> Harvester:
    if prepared_targets.get_kind() == PreparedPairs.KIND:
        return CandidateHarvester(wiring.nic, prepared_targets.get_models(), wiring.conf.harvester)
    else:
        raise ConfigurationException(f'Unable to provide harvester for targets of kind {prepared_targets.get_kind()}')
