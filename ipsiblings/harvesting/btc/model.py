from typing import Optional, List, Tuple


class BitcoinVersionInfo:
    def __init__(self, proto_ver: int, sub_ver: str, services: int, timestamp: int, height: int):
        self.proto_ver = proto_ver
        self.sub_ver = sub_ver
        self.services = services
        self.timestamp = timestamp
        self.height = height


class BitcoinConnection:
    def __init__(self, ip_ver: int, ip: str, port: int, first_seen: int, last_seen: int):
        self.ip_ver = ip_ver
        self.ip = ip
        self.port = port
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.verinfo: Optional[BitcoinVersionInfo] = None
        self.addr_infos: List[Tuple[int, int, str, int]] = []  # time, svc, ip, port

    def add_verinfo(self, verinfo: BitcoinVersionInfo):
        self.verinfo = verinfo

    def add_addrinfo(self, time: int, services: int, ip: str, port: int):
        self.addr_infos.append((time, services, ip, port))
