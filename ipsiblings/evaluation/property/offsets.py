# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
import numpy
from numpy.lib import recfunctions

from ipsiblings.evaluation.evaluatedsibling import SiblingProperty, EvaluatedSibling
from ipsiblings.evaluation.property.clean_series import NormTimestampSeries, NormSeriesProperty
from ipsiblings.evaluation.property.frequency import FrequencyProperty


class OffsetSeries:
    KEY_RECEPTION_TIME = 'reception_time'
    KEY_OFFSET = 'offset_secs'
    _DTYPE = numpy.dtype([(KEY_RECEPTION_TIME, numpy.float64), (KEY_OFFSET, numpy.float64)])

    def __init__(self, source: NormTimestampSeries, frequency):
        tsvals_secs = (source.ts_vals / frequency).round(decimals=6)
        offsets_raw = (tsvals_secs - source.reception_times) * 1000
        rounded_offsets = offsets_raw.round(decimals=6)
        data_unstructured = numpy.column_stack((source.reception_times, rounded_offsets))
        self.data = recfunctions.unstructured_to_structured(data_unstructured, dytpe=self._DTYPE)

    @property
    def reception_times(self):
        return self.data[self.KEY_RECEPTION_TIME]

    @property
    def offsets(self):
        return self.data[self.KEY_OFFSET]


class OffsetsProperty(SiblingProperty):
    """
    Converts TSval timestamps to seconds and provides raw offsets to actual reception timestamps.
    Depends on FrequencyProperty and CleanSeriesProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'OffsetsProperty':
        freq_prop = evaluated_sibling.contribute_property_type(FrequencyProperty)
        clean_prop = evaluated_sibling.contribute_property_type(NormSeriesProperty)
        return cls(
            OffsetSeries(clean_prop[4], freq_prop[4].frequency),
            OffsetSeries(clean_prop[6], freq_prop[6].frequency)
        )

    def __init__(self, offsets4: OffsetSeries, offsets6: OffsetSeries):
        self.offsets4 = offsets4
        self.offsets6 = offsets6

    def __getitem__(self, item) -> OffsetSeries:
        if item == 4:
            return self.offsets4
        elif item == 6:
            return self.offsets6
        else:
            raise KeyError
