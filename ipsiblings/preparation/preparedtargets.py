from typing import Dict, Union

from . import Target
from .. import liblog
from ..bootstrap.exception import DataException

log = liblog.get_root_logger()


class PreparedTargets:
    def __init__(self, targets: Dict[str, Target], kind: str):
        self.targets = targets
        self.kind = kind
        self.cleared = False
        self._has_timestamps = any([t.has_any_timestamp() for t in self.targets.values()])

    def _check_cleared(self):
        if self.cleared:
            raise DataException('Tried to access PreparedTargets after already cleared!')

    def __iter__(self):
        self._check_cleared()
        yield from self.targets.values()

    def __getitem__(self, item) -> Union[Target, None]:
        self._check_cleared()
        return self.targets.get(item)

    def get_target(self, ip_address) -> Union[Target, None]:
        return self[ip_address]

    def clear(self):
        self.targets = None
        self.cleared = True

    def has_timestamps(self):
        self._check_cleared()
        return self._has_timestamps

    def notify_timestamps_added(self):
        self._check_cleared()
        self._has_timestamps = any([t.has_any_timestamp() for t in self.targets.values()])

    def print_summary(self):
        self._check_cleared()
        log.info(f'Prepared {len(self.targets)} targets.')
