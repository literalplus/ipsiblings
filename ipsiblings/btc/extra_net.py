import ipaddress
import struct

from bitcoin.core import Serializable, ser_read, VarStringSerializer, SerializationTruncationError

# TODO: headers
# https://developer.bitcoin.org/reference/p2p_networking.html


PROTOCOL_VERSION = 70015


class SimpleSerializer(type):
    def __new__(mcs, name, bases, namespace, size=0, spec: bytes = b''):
        return super().__new__(mcs, name, bases, namespace)

    def __init__(cls, name, bases, namespace, size=0, spec: bytes = b''):
        super().__init__(name, bases, namespace)
        cls.spec = spec
        cls.size = size

    def read(cls, f):
        return struct.unpack(b'<' + cls.spec, ser_read(f, 8))[0]

    def write(cls, f, value):
        f.write(struct.pack(b'<' + cls.spec, value))


class UInt64(metaclass=SimpleSerializer, size=8, spec=b'Q'):
    pass


class Int64(metaclass=SimpleSerializer, size=8, spec=b'q'):
    pass


class Int32(metaclass=SimpleSerializer, size=4, spec=b'l'):
    pass


class Bool1(metaclass=SimpleSerializer, size=1, spec=b'?'):
    pass


class CShortAddress(Serializable):
    def __init__(self, services, ip_addr, port):
        self.services = 0  # uint64_t
        self.ip_addr: ipaddress.IPv6Address = ipaddress.IPv6Address("::")  # char[16] IPv6 in BE
        self.port = 0  # uint16_t BE

    @classmethod
    def stream_deserialize(cls, f, **kwargs):
        # For some reason, addr + port are Big-Endian, everything else is little
        return cls(
            UInt64.read(f),
            ipaddress.IPv6Address(struct.unpack(b'!s', ser_read(f, 16))[0]),
            struct.unpack(b"!H", ser_read(f, 2))[0]
        )

    def stream_serialize(self, f, **kwargs):
        UInt64.write(f, self.services)
        f.write(struct.pack(b"<sH", self.ip_addr.packed, self.port))

    def __repr__(self):
        return f"CShortAddress(svc={self.services}, addr={self.ip_addr}, port={self.port})"


class CVersionPacket(Serializable):
    USER_AGENT = "ipsiblings Research Scan"

    def __init__(self):
        self.version = PROTOCOL_VERSION  # int32_t
        self.services = 0  # uint64_t
        self.timestamp = 0  # int64_t required; seconds?
        self.addr_recv = CShortAddress()
        self.addr_trans = CShortAddress()
        self.nonce = 0  # uint64_t, ignored if zero
        self.user_agent_str = self.USER_AGENT  # string
        self.start_height = 0  # int32_t
        self.relay = False  # bool; set to True to receive inv/tx w/o filter

    @classmethod
    def stream_deserialize(cls, f, **kwargs):
        c = cls()
        c.version = Int32.read(f)
        c.services = UInt64.read(f)
        c.timestamp = Int64.read(f)
        c.addr_recv = CShortAddress.stream_deserialize(f)
        c.addr_trans = CShortAddress.stream_deserialize(f)
        c.nonce = UInt64.read(f)
        c.user_agent_str = VarStringSerializer.stream_deserialize(f)
        c.start_height = Int32.read(f)
        try:
            c.relay = Bool1.read(f)
        except SerializationTruncationError:
            pass  # this bit is optional
        return c

    def stream_serialize(self, f, **kwargs):
        Int32.write(f, self.version)
        UInt64.write(f, self.services)
        Int64.write(f, self.timestamp)
        self.addr_recv.stream_serialize(f)
        self.addr_trans.stream_serialize(f)
        UInt64.write(f, self.nonce)
        VarStringSerializer.stream_serialize(self.user_agent_str, f)
        Int32.write(f, self.start_height)
        Bool1.write(f, self.relay)

    def __repr__(self) -> str:
        return f'CVersionPacket(' \
               f'version={self.version},' \
               f'services={self.services},' \
               f'timestamp={self.timestamp},' \
               f'addr_recv={repr(self.addr_recv)},' \
               f'addr_trans={repr(self.addr_trans)},' \
               f'nonce={self.nonce},' \
               f'user_agent_str={self.user_agent_str},' \
               f'start_height={self.start_height},' \
               f'relay={self.relay}' \
               f')'
