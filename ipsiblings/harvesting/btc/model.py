from typing import List, Tuple

ADDR_SAVE_PENALTY_SECS = 2 * 60 * 60
ADDR_INACTIVE_THRESH_SECS = 24 * 60 * 60

# indices in addr info structure
AI_TIME = 0
AI_SVC = 1
AI_IP = 2
AI_PORT = 3


class BitcoinVersionInfo:
    def __init__(self, proto_ver: int, sub_ver: str, services: int, timestamp: int, height: int):
        self.proto_ver = proto_ver
        self.sub_ver = sub_ver
        self.services = services
        self.timestamp = timestamp
        self.height = height


class BitcoinConnection:
    def __init__(self, ip_ver: int, ip: str, port: int, first_seen: float, last_seen: float,
                 verinfo: BitcoinVersionInfo):
        self.ip_ver = ip_ver
        self.ip = ip
        self.port = port
        self.first_seen = first_seen
        self.last_seen = last_seen
        self.ver_info = verinfo
        self.addr_infos: List[Tuple[int, int, str, int]] = []  # time, svc, ip, port

    def add_addrinfo(self, time: int, services: int, ip: str, port: int):
        self.addr_infos.append((time, services, ip, port))

    def addr_ts_no_penalty(self, addrinfo: Tuple[int, int, str, int]) -> int:
        return addrinfo[0] - ADDR_SAVE_PENALTY_SECS

    def addr_age(self, addrinfo: Tuple[int, int, str, int]) -> int:
        return self.ver_info.timestamp - self.addr_ts_no_penalty(addrinfo)

    def was_active(self, addrinfo: Tuple[int, int, str, int]) -> bool:
        return self.addr_age(addrinfo) < ADDR_INACTIVE_THRESH_SECS
