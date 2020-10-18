import hashlib
import socket
import struct
from io import BytesIO
from typing import Optional, Tuple

import bitcoin
from bitcoin import messages
from bitcoin.core import b2x
from bitcoin.messages import MsgSerializable, CAddress, VarStringSerializer, ser_read

from ipsiblings import liblog

log = liblog.get_root_logger()


class MsgReadException(Exception):
    pass


class MsgDisconnectedException(Exception):
    pass


def _patched_deser_version(f: BytesIO):
    # This function taken from vv - expanded to have fRelay actually optional (LGPL v3)
    # https://github.com/petertodd/python-bitcoinlib/blob/b5540e8a8a138f2a4872c34ce4223b8f4e6856d9/bitcoin/messages.py#L137-L162
    c = messages.msg_version()
    c.nVersion = struct.unpack(b"<i", ser_read(f, 4))[0]
    if c.nVersion == 10300:
        c.nVersion = 300
    c.nServices = struct.unpack(b"<Q", ser_read(f, 8))[0]
    c.nTime = struct.unpack(b"<q", ser_read(f, 8))[0]
    c.addrTo = CAddress.stream_deserialize(f, True)
    if c.nVersion >= 106:
        c.addrFrom = CAddress.stream_deserialize(f, True)
        c.nNonce = struct.unpack(b"<Q", ser_read(f, 8))[0]
        c.strSubVer = VarStringSerializer.stream_deserialize(f)
        if c.nVersion >= 209:
            c.nStartingHeight = struct.unpack(b"<i", ser_read(f, 4))[0]
        else:
            c.nStartingHeight = None
    else:
        c.addrFrom = None
        c.nNonce = None
        c.strSubVer = None
        c.nStartingHeight = None
    if c.nVersion >= 70001:
        relay_bytes = f.read(1)
        # modified: fRelay is OPTIONAL for some reason, luckily it is the last field
        if len(relay_bytes) == 1:
            c.fRelay = struct.unpack(b"<B", relay_bytes)[0]
        else:
            c.fRelay = True
    else:
        c.fRelay = True
    return c


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
            recvbuf = sock.recv(msglen)
            if len(recvbuf) == 0:
                raise MsgDisconnectedException(b'peer disconnected (recv 0) - body')
            msgbuf = self._unfinished_msgbuf + recvbuf
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

    def _recv_header(self, sock: socket.socket) -> Optional[bytes]:
        recvbuf = sock.recv(self.HEADER_LEN)
        if len(recvbuf) == 0:
            raise MsgDisconnectedException(f'peer disconnected (recv 0) - header')
        elif len(recvbuf) != self.HEADER_LEN:
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
            msg_as_file = BytesIO(msgbuf)
            if cls == messages.msg_version:
                # Handles fRelay flag being optional
                return _patched_deser_version(msg_as_file)
            else:
                return cls.msg_deser(msg_as_file, proto_ver)
        else:
            log.warn(f'Received a message with unknown command {command}')
            return None
