# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
import numpy
import scipy.stats as scipy_stats

from ipsiblings.evaluation.evaluatedsibling import SiblingProperty, EvaluatedSibling
from ipsiblings.evaluation.property.clean_series import NormTimestampSeries, NormSeriesProperty


class FrequencyInfo:
    def __init__(self, clean_series: NormTimestampSeries):
        slope_raw, intercept, rval, pval, stderr = scipy_stats.linregress(
            clean_series.reception_times, clean_series.ts_vals
        )
        self.r_squared = rval * rval  # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
        self.frequency_raw = slope_raw
        self.frequency = round(slope_raw)  # Kohno et al. Section 4.3


class FrequencyProperty(SiblingProperty):
    """
    Provides the frequency of the remote clock.
    Depends on CleanSeriesProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'FrequencyProperty':
        clean_prop = evaluated_sibling.contribute_property_type(NormSeriesProperty)
        return cls(clean_prop[4], clean_prop[6])

    def __init__(self, clean4: NormTimestampSeries, clean6: NormTimestampSeries):
        self.freq4 = FrequencyInfo(clean4)
        self.freq6 = FrequencyInfo(clean6)
        self.diff = abs(self.freq4.frequency_raw - self.freq6.frequency_raw)
        self.r_squared_diff = abs(self.freq4.r_squared - self.freq6.r_squared)

    @property
    def mean_freq(self):
        return numpy.mean([self.freq4.frequency_raw, self.freq6.frequency_raw])

    def __getitem__(self, item) -> FrequencyInfo:
        if item == 4:
            return self.freq4
        elif item == 6:
            return self.freq6
        else:
            raise KeyError
