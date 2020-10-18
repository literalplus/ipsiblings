import hashlib
import logging
import socket
import struct
import time
from io import BytesIO
from typing import Optional, List, Tuple, Union

import bitcoin
from bitcoin import messages, net
from bitcoin.core import b2x
from bitcoin.core.serialize import SerializationTruncationError
from bitcoin.messages import MsgSerializable

from ipsiblings import liblog

log = liblog.get_root_logger()


class MsgReadException(Exception):
    pass


class MsgReceiver:
    HEADER_LEN = 4 + 12 + 4 + 4

    def __init__(self):
        self._unfinished_header: Optional[Tuple[bytes, bytes, int]] = None
        self._unfinished_msgbuf: bytes = b''

    def recv_message(self, sock: socket.socket, proto_ver: int) -> Tuple[bool, Optional[MsgSerializable]]:
        """
        Attempt to receive a packet from given socket.
        Returns a tuple of (finished, packet?).
        If not finished, call again once more data is available to read, packet will be None.
        If this raises, the connection state is undefined.
        """
        # Inspired by messages.stream_deserialize, adapted for non-blocking / huge messages
        checksum, command, msglen = self._recv_or_restore_header(sock)
        try:
            msgbuf = self._unfinished_msgbuf + sock.recv(msglen)
        except BlockingIOError as e:
            if e.errno == socket.EAGAIN:
                # no data yet; pretend we got empty response to try again later
                # select actually only guarantees one read, so this is to be expected in rare cases
                msgbuf = self._unfinished_msgbuf + b''
            else:
                raise e
        if len(msgbuf) < msglen:
            # peer flushed the stream before sending the whole message, remember what we got and come back to it
            self._unfinished_msgbuf = msgbuf
            self._unfinished_header = checksum, command, msglen
            return False, None
        else:
            # exactly the right length; longer cannot happen since recv() will only read up to bufsize bytes at once
            self._unfinished_msgbuf = b''
            self._unfinished_header = None
            self._verify_checksum(checksum, msgbuf)
            return True, self._process_msg(command, msgbuf, proto_ver)

    def _recv_or_restore_header(self, sock) -> Tuple[bytes, bytes, int]:
        if self._unfinished_header:
            # We have already received & parsed the header, just the body was not complete
            header = self._unfinished_header
        else:
            headerbuf = self._recv_header(sock)
            header = self._parse_header(headerbuf)
        return header

    def _recv_header(self, sock: socket.socket) -> bytes:
        recvbuf = sock.recv(self.HEADER_LEN)
        if len(recvbuf) != self.HEADER_LEN:
            raise MsgReadException(f'packet header, expected {self.HEADER_LEN} bytes, got {len(recvbuf)}')
        return recvbuf

    def _parse_header(self, recvbuf: bytes) -> Tuple[bytes, bytes, int]:
        magic_start = recvbuf[:4]
        pos = 4
        if magic_start != bitcoin.params.MESSAGE_START:
            raise MsgReadException(
                f"Invalid message start '{b2x(recvbuf[:4])}', expected '{b2x(bitcoin.params.MESSAGE_START)}'"
            )
        # read command until first NUL
        command = recvbuf[pos:pos + 12].split(b"\x00", 1)[0]
        pos += 12
        msglen = struct.unpack(b"<i", recvbuf[pos:pos + 4])[0]
        pos += 4
        checksum = recvbuf[pos:pos + 4]
        return checksum, command, msglen

    def _verify_checksum(self, checksum, msgbuf):
        intermediate_sum = hashlib.sha256(msgbuf).digest()
        final_sum = hashlib.sha256(intermediate_sum).digest()
        if checksum != final_sum[:4]:
            # Checksum only contains first four bytes of double-sha256 hash
            raise MsgReadException('Received a message not matching its checksum')

    def _process_msg(self, command: bytes, msgbuf: bytes, proto_ver: int) -> Optional[MsgSerializable]:
        if command in messages.messagemap:
            cls = messages.messagemap[command]
            return cls.msg_deser(BytesIO(msgbuf), proto_ver)
        else:
            log.warn(f'Received a message with unknown command {command}')
            return None


class Connection:
    def __init__(self, ip_version: int, ip: str, port: int):
        self.ip_version = ip_version
        self.ip = ip
        self.port = port
        self.receiver = MsgReceiver()
        self.sock = socket.socket(socket.AF_INET6 if ip_version == 6 else socket.AF_INET)

        log.debug(f'connecting to {(ip, port)}')
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
        return secs_since_last_useful_message > 60

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
            log.debug(f'Connection to {self.ip} reset, dropping.')
            return True, None
        except IOError as e:
            log.debug(f'IO error trying to read from {self.ip}', exc_info=e)
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
        elif isinstance(pkt, (messages.msg_getheaders, messages.msg_inv, messages.msg_alert)):
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
        debug_addrs: List[bytes] = []
        if log.isEnabledFor(logging.DEBUG):
            debug_addrs.append(b'text so that it doesnt evaluate to false')
        for addrx in pkt.addrs:
            addr: messages.CAddress = addrx
            self.addr_data.append((addr.nTime, addr.nServices, addr.ip, addr.port))
            if debug_addrs:
                debug_addrs.append(f'{addr.ip}-{addr.port}-{addr.nTime}-{addr.nServices};'.encode('utf-8'))
        hexdigest = '(none)'
        if debug_addrs:
            digest = hashlib.sha256(b'')
            for addrdata in sorted(debug_addrs):
                digest.update(addrdata)
            hexdigest = digest.hexdigest()[:8]
        log.debug(f'Actual addr from {self.ip} - {len(pkt.addrs)} entries, hash {hexdigest}')
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
