# libts/harvester.py
#
# (c) 2018 Marco Starke
#
import multiprocessing
import queue  # only exceptions
import random
import time
from datetime import timedelta
from typing import Tuple, List, Dict

import scapy.all as scapy

from ipsiblings import libconstants as const
from ipsiblings import logsetup
from ipsiblings.config import HarvesterConfig
from ipsiblings.harvesting.model import HarvestProvider
from ipsiblings.harvesting.tcpts._harvestreceiver import HarvestReceiver
from ipsiblings.model import Target, PreparedTargets, DataException, NicInfo

log = logsetup.get_root_logger()


class TcpTsHarvester(HarvestProvider):
    """
    Base class - TraceSetHarvester / CandidateHarvester

    Override __init__ and process_record functions.
    """

    def __init__(self, nic: NicInfo, conf: HarvesterConfig, targets: PreparedTargets):
        requested_run_count = int(conf.runtime / conf.ts_interval)
        super(TcpTsHarvester, self).__init__(conf.ts_interval, requested_run_count)

        self.conf = conf
        self.nic = nic
        if not targets.targets:
            raise DataException("Not harvesting empty candidate set")

        self.ipaddr_to_target: Dict[str, Target] = {target.address: target for target in targets}
        self.v4pkt = scapy.Ether() / scapy.IP() / self._make_tcp_layer(const.V4_PORT)
        self.v6pkt = scapy.Ether() / scapy.IPv6() / self._make_tcp_layer(const.V6_PORT)
        self.v4packets, self.v6packets = self._prepare_packets(targets)
        self.v4packets_length, self.v6packets_length = len(self.v4packets), len(self.v6packets)

        self.recv_proc = None
        self.receiver = HarvestReceiver(
            const.STOP_PORT, [const.V4_PORT, const.V6_PORT], self.mp_manager, self.stop_event
        )
        # typecodes - https://docs.python.org/3.7/library/array.html
        self.total_records = self.mp_manager.Value('I', 0)
        self.process_run_cnt = 0

        log.info(
            f'Constructed packets to be sent each run: '
            f'{self.v4packets_length} v4 packets / '
            f'{self.v6packets_length} v6 packets / '
            f'{self.v4packets_length + self.v6packets_length} overall'
        )

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
            if self.stop_event.is_set():
                log.debug('Stopping IPv4 sending process ...')
                break
            socket4.send(pkt)
        if log.isEnabledFor(logsetup.DEBUG):
            diff = time.time() - start_time
            log.debug(f'Finished IPv4 sending after {timedelta(seconds=diff)}.')
        socket4.close()

    def _send6(self):
        socket6 = scapy.conf.L2socket(iface=self.nic.name)
        start_time = time.time()
        # randomisation has significance at least for the fact that time difference between start of v4 and v6
        # series is used as an identifying metric
        for pkt in random.sample(self.v6packets, k=self.v6packets_length):
            if self.stop_event.is_set():
                log.debug('Stopping IPv6 sending process ...')
                break
            socket6.send(pkt)
        if log.isEnabledFor(logsetup.DEBUG):
            diff = time.time() - start_time
            log.debug(f'Finished IPv6 sending after {timedelta(seconds=diff)}.')
        socket6.close()

    def _do_single_run(self, run_number: int):
        self.send4 = multiprocessing.Process(target=self._send4, name=f'({run_number}) send4')
        self.send6 = multiprocessing.Process(target=self._send6, name=f'({run_number}) send6')
        self.send4.start()
        self.send6.start()

    def _handle_runs_finished(self):
        self.send4.join()
        self.send6.join()

    def start_async(self):
        self.recv_proc = multiprocessing.Process(target=self.receiver.run, name='HarvestReceiver')
        self.recv_proc.start()
        # allow enough time to setup sniffing process
        self.recv_proc.join(2)  # seconds
        super(TcpTsHarvester, self).start_async()

    def stop(self):
        log.debug('Harvester stop requested ...')
        self.stop_event.set()
        self._stop_sniff()

        if self._runs_finished.is_set():  # only necessary if runs are not already completed
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
        self.stop_event.set()

    def process_queued_results(self):
        self._process_results(2)

    def terminate_processing(self):
        self._process_results(self.conf.final_timeout)
        self._stop_sniff()
        log.info(f'TCP-TS: Total records processed: {self.total_records.value}')

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
        if self._runs_finished.is_set() and self.recv_proc.is_alive():
            log.info('Runs completed, waiting for final responses ...')
            self.recv_proc.join(timeout)

        self.process_run_cnt += 1
        nr_records = 0
        for _ in range(0, 5_000):
            if self._process_single_result(timeout):
                nr_records += 1
            else:
                self.total_records.value = self.total_records.value + nr_records
                break

    def _process_single_result(self, timeout: int) -> bool:
        try:
            record = self.receiver.response_queue.get(timeout=timeout)
            self.process_record(record)
            return True
        except queue.Empty:
            return False
        except Exception:
            log.exception('Unexpected error processing harvested records')
            return False

    def process_record(self, record):
        tcp_seq, ip, port, remote_ts, received_ts, tcp_options, ip_version = record
        target = self.ipaddr_to_target.get(ip)
        if target:
            target.handle_timestamp(remote_ts, received_ts, tcp_options)
        else:
            log.debug(f'Unexpected packet from IP {ip}')
