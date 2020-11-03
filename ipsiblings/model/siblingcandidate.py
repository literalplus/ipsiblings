# libsiblings/siblingcandidate.py
#
# (c) 2018 Marco Starke


from typing import Dict, Optional

from .target import Target
from .tcpopts import TcpOptions
from .timestampseries import TimestampSeries
from .. import logsetup

log = logsetup.get_root_logger()


class SiblingCandidate(object):
    """
    Represents a concrete SiblingCandidate.
    """

    def __init__(
            self, target4: Target, target6: Target
    ):
        self.series: Dict[int, TimestampSeries] = {
            4: target4.timestamps.as_series(),
            6: target6.timestamps.as_series(),
        }
        self.tcp_options: Dict[int, Optional[TcpOptions]] = {
            4: target4.tcp_options,
            6: target6.tcp_options,
        }
        self.domains = target4.domains.union(target6.domains)

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        if isinstance(other, SiblingCandidate):
            return self.key == other.key
        return NotImplemented

    def __str__(self):
        return f'SiblingCandidate - ' \
               f'{self.series[4].target_ip:<15} ({self.series[4].target_port:>7})' \
               f'   <=>   ' \
               f'{self.series[6].target_port:<7} {self.series[6].target_ip:<39}'

    @property
    def key(self):
        return self.series[4].target_ip, self.series[4].target_port, \
               self.series[6].target_ip, self.series[6].target_port
