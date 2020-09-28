# libts/harvester.py
#
# (c) 2018 Marco Starke
#
import abc
import multiprocessing
import queue  # only exceptions
import random
import threading
import time
from datetime import timedelta
from typing import Tuple, List, Dict

import scapy.all as scapy

from ipsiblings import libconstants as const
from ipsiblings import liblog
from ipsiblings.config import HarvesterConfig
from ipsiblings.harvesting._harvestreceiver import HarvestReceiver
from ipsiblings.model import Target, PreparedTargets, DataException, NicInfo

log = liblog.get_root_logger()


class Harvester(metaclass=abc.ABCMeta):
    """
    Base class - TraceSetHarvester / CandidateHarvester

    Override __init__ and process_record functions.
    """

    def __init__(self, nic: NicInfo, conf: HarvesterConfig, targets: PreparedTargets):
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
        if not targets.targets:
            raise DataException("Not harvesting empty candidate set")
        self.ipaddr_to_target: Dict[str, Target] = {target.address: target for target in targets}
        self.v4pkt = scapy.Ether() / scapy.IP() / self._make_tcp_layer(const.V4_PORT)
        self.v6pkt = scapy.Ether() / scapy.IPv6() / self._make_tcp_layer(const.V6_PORT)
        self.v4packets, self.v6packets = self._prepare_packets(targets)
        self.v4packets_length, self.v6packets_length = len(self.v4packets), len(self.v6packets)

        self.mp_manager = multiprocessing.Manager()
        self.stop_all = self.mp_manager.Value('B', 0)  # unsigned char
        self.receiver = HarvestReceiver(
            const.STOP_PORT, [const.V4_PORT, const.V6_PORT], self.mp_manager, self.stop_all
        )
        self.run_thread = None
        self.sniff_proc = None

        self.runs_stop_event = self.mp_manager.Event()
        self.runs_stop_event.clear()
        # typecodes - https://docs.python.org/3.7/library/array.html
        self.runs_completed = self.mp_manager.Value('B', 0)

        self.nr_runs = self.mp_manager.Value('I', int(self.conf.runtime / self.conf.interval))  # unsigned int
        self.run_counter = self.mp_manager.Value('I', 1)
        self.total_records = self.mp_manager.Value('I', 0)

        log.info(
            f'Constructed packets to be sent each run: '
            f'{self.v4packets_length} v4 packets / '
            f'{self.v6packets_length} v6 packets / '
            f'{self.v4packets_length + self.v6packets_length} overall'
        )

    def process_record(self, record):
        tcp_seq, ip, port, remote_ts, received_ts, tcp_options, ip_version = record
        target = self.ipaddr_to_target[ip]
        if target:
            target.handle_timestamp(remote_ts, received_ts, tcp_options)
        else:
            log.debug(f'Unexpected packet from IP {ip}')

    def _prepare_packets(self, targets: PreparedTargets) -> Tuple[List[scapy.Packet], List[scapy.Packet]]:
        v4packets, v6packets = [], []
        for target in targets:
            # Duplicate packets for an IP are prevented by targets working like a dict keyed by IP address
            if target.ip_version == 4:
                eth_packet = self.v4pkt.copy()
                vpackets = v4packets
            else:
                eth_packet = self.v6pkt.copy()
                vpackets = v6packets
            ip_packet = eth_packet.payload
            ip_packet.dst = target.address
            tcp_packet = ip_packet.payload
            tcp_packet.dport = int(target.port)
            vpackets.append(eth_packet)
        return v4packets, v6packets

    def _make_tcp_layer(self, port: int):
        return scapy.TCP(
            sport=port, flags='S', options=[
                ('Timestamp', (const.TS_INITIAL_VAL, 0)),
                ('WScale', 0)
            ]
        )  # /scapy.Raw(load = const.PACKET_RESEARCH_MESSAGE)

    def _send4(self):
        socket4 = scapy.conf.L2socket(iface=self.nic.name)
        start_time = time.time()
        # randomisation has significance at least for the fact that time difference between start of v4 and v6
        # series is used as an identifying metric
        for pkt in random.sample(self.v4packets, k=self.v4packets_length):
            if self.stop_all.value == 1:
                log.debug('Stopping IPv4 sending process ...')
                break
            socket4.send(pkt)
        if log.isEnabledFor(liblog.DEBUG):
            diff = time.time() - start_time
            log.debug(f'Finished IPv4 sending after {timedelta(seconds=diff)}.')
        socket4.close()

    def _send6(self):
        socket6 = scapy.conf.L2socket(iface=self.nic.name)
        start_time = time.time()
        # randomisation has significance at least for the fact that time difference between start of v4 and v6
        # series is used as an identifying metric
        for pkt in random.sample(self.v6packets, k=self.v6packets_length):
            if self.stop_all.value == 1:
                log.debug('Stopping IPv6 sending process ...')
                break
            socket6.send(pkt)
        if log.isEnabledFor(liblog.DEBUG):
            diff = time.time() - start_time
            log.debug(f'Finished IPv6 sending after {timedelta(seconds=diff)}.')
        socket6.close()

    def _run(self):
        self.send4 = multiprocessing.Process(target=self._send4, name='({0}) send4'.format(self.run_counter.value))
        self.send6 = multiprocessing.Process(target=self._send6, name='({0}) send6'.format(self.run_counter.value))
        self.send4.start()
        self.send6.start()

    def _start(self):
        """
        Repeat the _run function call at each interval until the runs_stop_event is set or
        the requested number of runs is reached.
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
        self.sniff_proc = multiprocessing.Process(target=self.receiver.run, name='HarvestReceiver')
        self.sniff_proc.start()
        # allow enough time to setup sniffing process
        self.sniff_proc.join(const.START_SNIFF_PROCESS_DELAY)

        own_thread = threading.Thread(target=self._start)
        own_thread.start()
        return own_thread

    def stop(self):
        log.debug('Harvester stop requested ...')
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

    def _stop_sniff(self):
        # send STOP packet to localhost - to be sure do this for IPv4 and IPv6
        p4 = scapy.Ether() / scapy.IP(dst='127.0.0.1') / self.receiver.provide_stop_tcp_packet()
        p6 = scapy.Ether() / scapy.IPv6(dst='::1') / self.receiver.provide_stop_tcp_packet()
        scapy.sendp(p4, verbose=0)
        scapy.sendp(p6, verbose=0)

    def finished(self):
        """
        True if and only if all runs and sending processes have finished.
        Waiting for responses is up to the caller.
        """
        return bool(self.runs_completed.value)

    def wait(self, timeout):
        """
        Wait for a given timeout.
        Timeout must be a positive number otherwise this will cause a livelock.
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
        Queries the response_queue for records and writes them to the result object.

        Waits 'timeout' seconds for data, if no data is available return.

        If harvesting has finished and this is the last call for result assignment,
        the function blocks for 'timeout' seconds and performs as usual after this waiting period.
        During the last call, it also stops the sniffing process which means no further
        calls to functions which control the processes are necessary.

        Keep in mind that if the timeout parameter is >= the sending interval, the function
        will (probably) never return since there will always be new data available within the given timeout ...

        :return the number of records processed in this call
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
                record = self.receiver.response_queue.get(timeout=timeout)
                self.process_record(record)
                nr_records = nr_records + 1
            except queue.Empty:
                if nr_records > 0:
                    log.debug(f'Current number of records processed: {nr_records}')
                    self.total_records.value = self.total_records.value + nr_records
                else:
                    if not finished_before_call:
                        log.debug('No records processed')
                break
            except Exception:
                log.exception('Unexpected error processing harvested records')
                break

        if finished_before_call:
            self._stop_sniff()

        return nr_records
