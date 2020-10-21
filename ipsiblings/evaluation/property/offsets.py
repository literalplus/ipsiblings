# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
from typing import Dict, Set, Optional

import numpy
from numpy.lib import recfunctions

from ipsiblings import liblog
from ipsiblings.evaluation.model.property import FamilySpecificSiblingProperty
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.property.frequency import FrequencyProperty
from ipsiblings.evaluation.property.norm_series import NormTimestampSeries, NormSeriesProperty

log = liblog.get_root_logger()


class OffsetSeries:
    KEY_RECEPTION_TIME = 'reception_time'
    KEY_OFFSET = 'offset_secs'
    DTYPE = numpy.dtype([(KEY_RECEPTION_TIME, numpy.float64), (KEY_OFFSET, numpy.float64)])

    def __init__(self, data: numpy.ndarray):
        self.data = data

    @classmethod
    def from_norm(cls, source: NormTimestampSeries, frequency) -> 'OffsetSeries':
        tsvals_secs = (source.ts_vals / frequency).round(decimals=6)
        offsets_raw = (tsvals_secs - source.reception_times) * 1000
        rounded_offsets = offsets_raw.round(decimals=6)
        data_unstructured = numpy.column_stack((source.reception_times, rounded_offsets))
        data = recfunctions.unstructured_to_structured(data_unstructured, dtype=cls.DTYPE)
        return cls(data)

    @property
    def reception_times(self) -> numpy.ndarray:
        return self.data[self.KEY_RECEPTION_TIME]

    @property
    def offsets(self) -> numpy.ndarray:
        return self.data[self.KEY_OFFSET]

    def has_data(self) -> bool:
        return len(self) > 2  # no meaningful conclusions can be drawn from less than three timestamps

    def __len__(self):
        return len(self.data)


class OffsetsProperty(FamilySpecificSiblingProperty[Optional[OffsetSeries]]):
    """
    Converts TSval timestamps to seconds and provides raw offsets to actual reception timestamps.
    Depends on FrequencyProperty and CleanSeriesProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'Optional[OffsetsProperty]':
        freq_prop = evaluated_sibling.contribute_property_type(FrequencyProperty)
        clean_prop = evaluated_sibling.contribute_property_type(NormSeriesProperty)
        if freq_prop and (freq_prop[4].frequency == 0 or freq_prop[6] == 0):
            log.debug(f'Frequency is zero for {evaluated_sibling}')
            return None
        if freq_prop and clean_prop:
            def provider(ip_version: int):
                return OffsetSeries.from_norm(clean_prop[ip_version], freq_prop[ip_version].frequency)

            return cls(
                cls._cache_get_or(evaluated_sibling[4], provider),
                cls._cache_get_or(evaluated_sibling[6], provider),
            )
        else:
            return None

    def __init__(self, offsets4: Optional[OffsetSeries], offsets6: Optional[OffsetSeries]):
        self.data4 = offsets4
        self.data6 = offsets6

    def export(self) -> Dict[str, int]:
        return {'len4': len(self[4]), 'len6': len(self[6])}

    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return {'len4', 'len6'}
