from typing import Tuple

import numpy


class TimestampSeries:
    """
    Immutable timestamp data, backed by a NumPy array.
    Combines timestamps collected for a single (IP, port, address family) tuple.
    See also Timestamps.
    """
    KEY_TS_VAL = 'ts_val'
    KEY_RECEPTION_TIME = 'reception_time'
    DTYPE = numpy.dtype([(KEY_TS_VAL, numpy.int32), (KEY_RECEPTION_TIME, numpy.float64)])

    def __init__(self, key: Tuple[int, str, int], data: numpy.ndarray):
        self.ip_version, self.target_ip, self.target_port = key
        self.data = data

    def __len__(self):
        return self.data.size

    @property
    def key(self):
        return self.ip_version, self.target_ip, self.target_port

    def has_data(self):
        return len(self) > 0

    @property
    def reception_times(self) -> numpy.ndarray:
        return self.data[self.KEY_RECEPTION_TIME]

    @property
    def ts_vals(self) -> numpy.ndarray:
        return self.data[self.KEY_TS_VAL]

    @property
    def first_ts_val(self) -> int:
        if not self.has_data():
            return 0
        return self.ts_vals[0]

    @property
    def first_reception_time(self) -> float:
        if not self.has_data():
            return 0
        return self.reception_times[0]
