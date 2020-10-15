import queue
import random
import select
import socket
import threading
import time
from multiprocessing.managers import SyncManager
from typing import Dict, Optional, Tuple, List, Union

from bitcoin import messages, net
from bitcoin.messages import MsgSerializable


class Connection:
    def __init__(self, ip: str, port: int):
        self.ip = ip
        self.port = port
        self.sock = socket.socket()
        self.sock.connect((ip, port))
        self.fileno = self.sock.fileno()
        self._file = self.sock.makefile(mode='rwb')
        self.first_seen = time.time()
        self.last_seen = time.time()
        self.ver_pkt: Optional[messages.msg_version] = None
        self.addr_data: List[Tuple[int, int, str, int]] = []  # time, svc, ip, port

    def send_pkt(self, pkt: MsgSerializable):
        pkt.stream_serialize(self._file)

    def _make_version(self):
        msg = messages.msg_version()
        msg.nVersion = 70002
        msg.addrTo.ip = self.ip
        msg.addrTo.port = self.port
        # Satoshi client does not fill addrFrom either ->
        # https://github.com/bitcoin/bitcoin/blob/c2c4dbaebd955ad2829364f7fa5b8169ca1ba6b9/src/net_processing.cpp#L494
        return msg

    def should_expire(self):
        secs_since_last_seen = time.time() - self.last_seen
        return secs_since_last_seen > 60

    def close(self):
        self._file.close()
        self.sock.close()

    def handle_pkt(self) -> Union[MsgSerializable, None, False]:
        protocol_version = self.ver_pkt.protover if self.ver_pkt else net.PROTO_VERSION
        pkt = MsgSerializable.stream_deserialize(self._file, protocol_version)
        self.last_seen = time.time()
        if isinstance(pkt, messages.msg_version):
            self.ver_pkt = pkt
        elif isinstance(pkt, messages.msg_verack):
            # TODO: can we send this here? in tests, we needed to wait for more packets
            return messages.msg_getaddr()
        elif isinstance(pkt, messages.msg_addr) and len(pkt.addrs) > 10:
            # we do not want to process forwarded addresses (mostly meaningless, messes up invariants)
            # also, the peer will advertise the address we connected which (also meaningless)
            # responses to GETADDR will usually have a sufficient amount
            for addrx in pkt.addrs:
                addr: messages.CAddress = addrx
                self.addr_data.append((addr.nTime, addr.nServices, addr.ip, addr.port))
            return False
        return None

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
            (self.ip, self.port),
            (self.first_seen, self.last_seen),
            verinfo,
            self.addr_data,
        )


class ConnectionHandler:
    def __init__(self, mp_manager: SyncManager, stop_event: threading.Event, closing_event: threading.Event):
        self.connect_q = mp_manager.Queue()
        self.result_q = mp_manager.Queue()
        self._stop_event = stop_event
        self._closing_event = closing_event
        self.all_connections_created = mp_manager.Event()
        self.all_connections_closed = mp_manager.Event()
        self.connections: Dict[int, Connection] = {}
        self.sock_filenos: List[int] = []  # cache this, select() takes a list

    def run(self):
        while not self._stop_event.is_set():
            self._handle_connection_creation()
            self._handle_sock_reading()
            self._handle_connection_expiry()
        for conn in self.connections.values():
            self._close_conn(conn)

    def _handle_connection_creation(self):
        if self.all_connections_created.is_set():
            return
        try:
            (ip, port) = self.connect_q.get(block=False)
            self._connect_to(ip, port)
        except queue.Empty:
            if self._closing_event.is_set():
                self.all_connections_created.set()

    def _connect_to(self, ip: str, port: int):
        conn = Connection(ip, port)
        if conn.fileno in self.connections:
            self._close_conn(self.connections[conn.fileno])
        self.connections[conn.fileno] = conn
        self.sock_filenos.append(conn.fileno)

    def _handle_sock_reading(self):
        ready_to_read, _, _ = select.select(
            self.sock_filenos, [], [], 0.1  # timeout in seconds
        )
        for readable_sock in ready_to_read:
            fileno = readable_sock.fileno()
            conn = self.connections[fileno]
            response = conn.handle_pkt()
            if response is False:
                self._close_conn(conn)
            elif response is not None:
                conn.send_pkt(response)

    def _close_conn(self, conn: Connection):
        conn.close()
        self.sock_filenos.remove(conn.fileno)
        self.connections.pop(conn.fileno)
        self.result_q.put(conn.to_tuple())
        if not self.connections and self.all_connections_created.is_set():
            self.all_connections_closed.set()

    def _handle_connection_expiry(self):
        if random.uniform(0, 100) > 80:
            for conn in self.connections.values():
                if conn.should_expire():
                    self._close_conn(conn)
