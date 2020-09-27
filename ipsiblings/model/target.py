from typing import List, Tuple, Optional

from .tcpopts import TcpOptions
from .timestamps import Timestamps


class Target:
    def __init__(self, key: Tuple[int, str, int]):
        self.ip_version, self.address, self.port = key
        self.tcp_options: Optional[TcpOptions] = None
        self.timestamps = Timestamps(self.ip_version, self.address, self.port)
        self.domains = set()

    @classmethod
    def make_key(cls, ip_version, address, port) -> Tuple:
        return ip_version, address, port

    @classmethod
    def key_and_rest_from(cls, it: List) -> Tuple[Tuple[int, str, int], List]:
        ip_version_raw, address, port_raw, *rest = it
        return cls.make_key(int(ip_version_raw), address, int(port_raw)), rest

    @property
    def key(self):
        return self.make_key(self.ip_version, self.address, self.port)

    def has_any_timestamp(self):
        return self.timestamps.has_any_timestamp

    def add_domain(self, domain):
        self.domains.add(domain)

    def handle_timestamp(self, remote_ts, received_ts, tcp_options):
        self.timestamps.add_timestamp(remote_ts, received_ts)
        if tcp_options and not self.tcp_options:
            self.tcp_options = TcpOptions(tcp_options)
