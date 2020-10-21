import socket
import time
from typing import Optional, List, Tuple, Union

from bitcoin import messages, net
from bitcoin.core.serialize import SerializationTruncationError
from bitcoin.messages import MsgSerializable

from ipsiblings import liblog
from ipsiblings.harvesting.btc._msgreceiver import MsgReceiver, MsgDisconnectedException, MsgReadException

log = liblog.get_root_logger()


class Connection:
    def __init__(self, ip_version: int, ip: str, port: int):
        self.ip_version = ip_version
        self.ip = ip
        self.port = port
        self.receiver = MsgReceiver()
        self.sock = socket.socket(socket.AF_INET6 if ip_version == 6 else socket.AF_INET)

        self.sock.settimeout(1)  # second
        self.sock.connect((ip, port))
        self.sock.settimeout(None)
        self.sock.setblocking(False)
        self.fileno = self.sock.fileno()

        self.first_seen = time.time()
        self.last_seen = time.time()
        self.last_useful = time.time()

        self.ver_pkt: Optional[messages.msg_version] = None
        self.addr_data: List[Tuple[int, int, str, int]] = []  # time, svc, ip, port
        self.verack_received = False
        self.getaddr_sent = False
        self.pkt_count = 0

        self.send_pkt(self._make_version())  # otherwise they won't talk to us :(

    def send_pkt(self, pkt: MsgSerializable):
        self.sock.send(pkt.to_bytes())

    def _make_version(self):
        msg = messages.msg_version()
        msg.nVersion = 70002
        msg.addrTo.ip = self.ip
        msg.addrTo.port = self.port
        # Satoshi client does not fill addrFrom either ->
        # https://github.com/bitcoin/bitcoin/blob/c2c4dbaebd955ad2829364f7fa5b8169ca1ba6b9/src/net_processing.cpp#L494
        return msg

    def should_expire(self):
        secs_since_last_useful_message = time.time() - self.last_useful
        # Peers usually take below 30s (but always some time) to respond, times around 100s have been observed
        return secs_since_last_useful_message > 150

    def close(self):
        self.sock.close()

    def handle_pkt(self) -> Union[MsgSerializable, None, bool]:
        """
        Attempts to receive a packet.
        Returns either the next packet to send, None if no reply is intended, and False to request disconnection.
        """
        finished, pkt = self._try_receive()
        if not pkt:
            if finished:
                return False  # read everything, still no packet -> disconnect on error
            else:
                return None  # peer send buffer was full, noted what we have so far, wait for rest
        return self._handle_pkt(pkt)

    def _try_receive(self) -> Tuple[bool, Optional[MsgSerializable]]:
        try:
            protocol_version = self.ver_pkt.protover if self.ver_pkt else net.PROTO_VERSION
            finished, pkt = self.receiver.recv_message(self.sock, protocol_version)
            if finished:
                self.last_seen = time.time()
                self.pkt_count += 1
            return finished, pkt
        except SerializationTruncationError as e:
            # a packet impl expected to read more bytes than we actually got -> protocol error
            log.debug(f'Unexpected byte count from {self.ip}', exc_info=e)
            return True, None
        except ConnectionResetError:
            # connection reset is nothing too unusual, but mucho spam if we connect to 10k peers
            return True, None
        except IOError as e:
            log.debug(f'IO error trying to read from {self.ip}', exc_info=e)
            return True, None
        except MsgDisconnectedException:
            # peer disconnected us, accept that, nothing special per se
            return True, None
        except MsgReadException as e:
            log.debug(f'Protocol error from {self.ip} - {repr(e)}')
            return True, None

    def _handle_pkt(self, pkt):
        if isinstance(pkt, messages.msg_version):
            self.ver_pkt = pkt
            self.last_useful = time.time()
            return messages.msg_verack()
        elif isinstance(pkt, messages.msg_ping):
            return messages.msg_pong(nonce=pkt.nonce)
        elif isinstance(pkt, messages.msg_verack):
            self.verack_received = True
            self.last_useful = time.time()
            return None
        elif isinstance(pkt, messages.msg_addr):
            if len(pkt.addrs) > 10:
                self._handle_addr(pkt)
                return False  # disconnect, we got what we wanted
            else:
                return None  # usually either forwarded or self-announcement, neither is useful
        elif isinstance(pkt, (messages.msg_getheaders, messages.msg_inv, messages.msg_alert, messages.msg_getblocks)):
            pass  # irrelevant but common, don't want to spam log
        else:
            log.debug(f'other pkt from -> {self.ip}: {pkt}')
        if self.pkt_count > 6 and not self.getaddr_sent:
            self.getaddr_sent = True
            # some clients advertise their own address first, and only then seem to properly react to getaddr
            # and sometimes it seems to be unrelated to that, so just wait a few packets, then it usually
            # works, except for clients that just don't reply at all, which also happens
            # (which is why we have last_useful to expire connections that don't yield addresses in reasonable time)
            return messages.msg_getaddr()
        return None

    def _handle_addr(self, pkt: messages.msg_addr):
        for addrx in pkt.addrs:
            addr: messages.CAddress = addrx
            self.addr_data.append((addr.nTime, addr.nServices, addr.ip, addr.port))
        self.last_useful = time.time()

    def to_tuple(self):
        # who, when, version, addresses
        if self.ver_pkt:
            verinfo = (
                self.ver_pkt.protover, self.ver_pkt.strSubVer,
                self.ver_pkt.nServices, self.ver_pkt.nTime,
                self.ver_pkt.nStartingHeight,
            )
        else:
            verinfo = None
        return (
            (self.ip_version, self.ip, self.port),
            (self.first_seen, self.last_seen),
            verinfo,
            self.addr_data,
        )
