from typing import List, Tuple


class HarvestedTimestamps:
    """Collects timestamps harvested for a single IP, port, and address family."""

    def __init__(self, ip_version: int, target_ip: str, target_port: int):
        self.ip_version = ip_version
        self.target_ip = target_ip
        self.target_port = target_port
        self._timestamps: List[Tuple[int, float]] = []

    def add_timestamp(self, remote_ts: int, local_ts: float):
        """Parameters as defined in timestamps property"""
        self._timestamps.append((remote_ts, local_ts))

    @property
    def timestamps(self) -> List[Tuple[int, float]]:
        """
        List of tuples representing timestamp information related to a single TCP packet each, containing these fields:

        remote_ts: int Remote timestamp as observed in the TCP timestamp option, TSval.
        Granularity is not defined by the TCP standard.

        local_ts: float Reception timestamps captured by the local TCP stack, in seconds as floating-point
        value. This is similar to time.time() and may be passed to datetime.fromtimestamp().
        """
        return self._timestamps
