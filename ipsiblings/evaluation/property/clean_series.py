import numpy
from numpy.lib import recfunctions

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, FamilySpecificSiblingProperty
from ipsiblings.model import TimestampSeries

# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)


# used to check if overflow of timestamp counter occurred
# ~1000 timestamp ticks -> 1 to 10 seconds (frequencies of 1Hz to 1000Hz according to RFC)
TS_OVERFLOW_THRESHOLD = 1000


class NormTimestampSeries(TimestampSeries):
    def __init__(self, source: TimestampSeries, clean_reception_times: numpy.ndarray, clean_ts_vals: numpy.ndarray):
        unstructured_data = numpy.array([clean_reception_times, clean_ts_vals]).T
        structured_data = recfunctions.unstructured_to_structured(unstructured_data, dtype=self._DTYPE)
        super(NormTimestampSeries, self).__init__(source.key, structured_data)


class NormSeriesProperty(FamilySpecificSiblingProperty[NormTimestampSeries]):
    """
    Provides normalised timestamp series for each address family.
    Each of these series has effects of obvious integer overflows removed.
    Further, the reception times and TSval values are normalised such that each starts at zero.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'NormSeriesProperty':
        clean4 = cls._clean_data(evaluated_sibling.series[4])
        clean6 = cls._clean_data(evaluated_sibling.series[6])
        return cls(clean4, clean6)

    @classmethod
    def _clean_data(cls, series: TimestampSeries) -> NormTimestampSeries:
        reception_times = series.reception_times
        clean_reception_times = numpy.zeros(len(reception_times) - 1)
        ts_vals = series.ts_vals
        clean_ts_vals = numpy.zeros(len(ts_vals) - 1)
        first_ts_val = series.first_ts_val
        first_reception_time = series.first_reception_time

        overflow_adjustment = 0
        for i in range(1, len(series)):
            # NOTE: previous implementation also wrapped the reception timestamps.
            # These however are Unix timestamps, which we do not expect to wrap
            sequence_wrapped = ts_vals[i] + TS_OVERFLOW_THRESHOLD < ts_vals[i - 1]
            previous_close_to_overflow = ts_vals[i - 1] > 2 ** 31
            if sequence_wrapped and previous_close_to_overflow:
                # TSval is an int32; Python can deal with much larger numbers, so multiple overflows are okay
                overflow_adjustment += 2 ** 32
            clean_reception_times[i - 1] = reception_times[i] - first_reception_time
            clean_ts_vals[i - 1] = ts_vals[i] + overflow_adjustment - first_ts_val

        return NormTimestampSeries(series, clean_reception_times, clean_ts_vals)

    def __init__(self, clean4: NormTimestampSeries, clean6: NormTimestampSeries):
        self.data4 = clean4
        self.data6 = clean6
