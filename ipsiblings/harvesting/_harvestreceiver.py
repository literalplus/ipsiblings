import random
import select
from typing import List, Union, Tuple

import scapy.all as scapy

from ipsiblings import liblog

log = liblog.get_root_logger()


class HarvestReceiver:
    """Handles reception of response packets for a Harvester."""

    def __init__(self, stop_port: int, payload_ports: List[int], mp_manager, stop_all):
        self.stop_port = stop_port
        self.stop_payload = f'STOP_{random.getrandbits(64)}'
        all_ports = payload_ports + [stop_port]
        self.packet_filter = f'((tcp) and (' \
                             " or ".join([f'(dst port {port})' for port in all_ports]) + \
                             f'))'
        self.response_queue = mp_manager.Queue()
        self.stop_all = stop_all  # stop flag

    def run(self):
        # https://github.com/secdev/scapy/issues/989 - own sniff implementation

        # from that issue, might be interesting to change to AsyncSniffer: https://github.com/secdev/scapy/pull/1999

        with scapy.conf.L2listen(filter=self.packet_filter) as sock:
            while self.stop_all.value != 1:
                try:  # prevent sniff process to terminate on error (excludes KeyboardInterrupt and SystemExit)
                    rlist = select.select([sock], [], [])
                    if not rlist:
                        continue
                    packet = sock.recv()
                    if self._is_stop_packet(packet):
                        log.debug(f'Received signal packet, stopping HarvestReceiver.')
                        break
                    remote_ts, echo_ts = self._extract_tcp_ts(packet)
                    if not remote_ts:
                        continue  # if no timestamp available ignore packet
                    self.response_queue.put(self._packet_to_record(packet, remote_ts))
                except Exception as e:
                    log.warning('[Ignored] Sniff Exception: {0} - {1}'.format(type(e).__name__, e))
                    continue
            log.debug('Sniff process terminated.')

    def _is_stop_packet(self, packet: scapy.Packet):
        return packet[scapy.TCP].dport == self.stop_port and \
               scapy.Raw in packet and \
               packet[scapy.Raw].load.decode('utf-8') == self.stop_payload

    def _extract_tcp_ts(self, packet: scapy.Packet) -> Tuple[Union[int, None], int]:
        """
        Returns the TCP options timestamp tuple (TSval, TSecr) if available or otherwise (None, 0).
        The first value is the remote timestamp and the second one is echoed from our last timestamp.
        TSecr should only be set on ACK packets and must be ignored on others.
        ref: https://tools.ietf.org/html/rfc7323#section-3
        """
        try:
            for opt in packet[scapy.TCP].options:
                if opt[0] == 'Timestamp':
                    return opt[1]
        except Exception:  # Not sure what this is supposed to catch besides KeyError
            log.exception('Unable to extract timestamp')
        return None, 0

    def _packet_to_record(self, packet, remote_ts):
        # (tcp_seq, node_ip, remote_port, remote_ts, received_ts, tcp_options, ip_version)
        record = (
            packet.payload.payload.ack - 1,
            packet.payload.src,
            packet.payload.payload.sport,
            remote_ts,
            packet.time,
            packet[scapy.TCP].options,
            packet.payload.version
        )
        # local timestamps are provided as e.g. 1541763777.398191 (microseconds)
        # remote timestamps in seconds only
        return record

    def provide_stop_tcp_packet(self):
        return scapy.TCP(dport=self.stop_port) / scapy.Raw(load=self.stop_payload)
