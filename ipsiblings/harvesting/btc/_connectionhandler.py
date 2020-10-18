import queue
import random
import select
import threading
import time
from multiprocessing.managers import SyncManager
from typing import Dict, Tuple, List

from ipsiblings import liblog
from ipsiblings.harvesting.btc._connection import Connection

log = liblog.get_root_logger()


class ConnectionHandler:
    def __init__(self, mp_manager: SyncManager, stop_event: threading.Event, closing_event: threading.Event):
        self.connect_q = mp_manager.Queue()
        self.result_q = mp_manager.Queue()
        self._stop_event = stop_event
        self._closing_event = closing_event
        self.all_connections_created = mp_manager.Event()
        self.all_connections_closed = mp_manager.Event()
        self.last_all_closed = time.time()
        self.connections: Dict[int, Connection] = {}
        self.sock_filenos: List[int] = []  # cache this, select() takes a list
        self.connected_targets: Dict[Tuple[int, str, int], Connection] = {}

    def run(self):
        while not self._stop_event.is_set():
            try:
                self._handle_connection_creation()
                self._handle_sock_reading()
                self._handle_connection_expiry()
            except Exception:
                log.exception(f'Error handling connections')
            except KeyboardInterrupt:
                log.info('Received keyboard interrupt, closing connections.')
                break
        for conn in list(self.connections.values()):
            self._close_conn(conn)

    def _handle_connection_creation(self):
        if self.all_connections_created.is_set() or len(self.connections) > 10:
            return
        key = None
        try:
            key = self.connect_q.get(block=False)
            self._connect_to(key)
        except queue.Empty:
            if self._closing_event.is_set():
                self.all_connections_created.set()
        except ConnectionRefusedError:
            log.debug(f'Connection to {key} refused')
        except Exception:
            log.exception(f'Failed to connect to {key}')

    def _connect_to(self, key: Tuple[int, str, int]):
        if key in self.connected_targets:
            log.debug(f'Still connected to {key}, disconnecting first.')
            self._close_conn(self.connected_targets[key])
        conn = Connection(key[0], key[1], key[2])
        if conn.fileno in self.connections:
            self._close_conn(self.connections[conn.fileno])
        self.connections[conn.fileno] = conn
        self.sock_filenos.append(conn.fileno)
        self.connected_targets[key] = conn

    def _handle_sock_reading(self):
        ready_to_read, _, exceptional = select.select(
            self.sock_filenos, [], self.sock_filenos, 0.1  # timeout in seconds
        )
        for readable_fileno in ready_to_read:
            conn = self.connections[readable_fileno]
            response = conn.handle_pkt()
            if response is False:
                self._close_conn(conn)
            elif response is not None:
                conn.send_pkt(response)
        for exceptional_fileno in exceptional:
            log.warn(f'Socket marked exceptional by select(), dropping connection.')
            conn = self.connections[exceptional_fileno]
            self._close_conn(conn)

    def _close_conn(self, conn: Connection):
        log.debug(f'Disconnecting from {conn.ip}.')
        conn.close()
        self.sock_filenos.remove(conn.fileno)
        self.connections.pop(conn.fileno)
        self.result_q.put(conn.to_tuple())
        self.connected_targets.pop((conn.ip_version, conn.ip, conn.port))
        if not self.connections:
            if self.all_connections_created.is_set():
                self.all_connections_closed.set()
            secs_since_last_all_closed = time.time() - self.last_all_closed
            log.debug(f'All connections closed for now, {secs_since_last_all_closed:.2f}s since this last happened.')

    def _handle_connection_expiry(self):
        if random.uniform(0, 100) > 80:
            expired_connections = [
                (fileno, conn) for (fileno, conn) in self.connections.items() if conn.should_expire()
            ]
            for fileno, conn in expired_connections:
                log.debug(f'Expiring connection to {conn.ip}')
                self._close_conn(conn)
                self.connections.pop(fileno)
