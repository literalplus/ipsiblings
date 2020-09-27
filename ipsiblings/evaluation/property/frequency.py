# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
from typing import Dict, Set, Optional

import numpy
import scipy.stats as scipy_stats

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, FamilySpecificSiblingProperty
from ipsiblings.evaluation.property.clean_series import NormTimestampSeries, NormSeriesProperty


class FrequencyInfo:
    def __init__(self, clean_series: NormTimestampSeries):
        slope_raw, intercept, rval, pval, stderr = scipy_stats.linregress(
            clean_series.reception_times, clean_series.ts_vals
        )
        self.r_squared = rval * rval  # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
        self.frequency_raw = slope_raw
        self.frequency = round(slope_raw)  # Kohno et al. Section 4.3


class FrequencyProperty(FamilySpecificSiblingProperty[FrequencyInfo]):
    """
    Provides the frequency of the remote clock.
    Depends on CleanSeriesProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'Optional[FrequencyProperty]':
        clean_prop = evaluated_sibling.contribute_property_type(NormSeriesProperty)
        if not clean_prop:
            return None
        return cls(clean_prop[4], clean_prop[6])

    def __init__(self, clean4: NormTimestampSeries, clean6: NormTimestampSeries):
        self.data4 = FrequencyInfo(clean4)
        self.data6 = FrequencyInfo(clean6)
        self.diff = abs(self[4].frequency_raw - self[6].frequency_raw)
        self.r_squared_diff = abs(self[4].r_squared - self[6].r_squared)

    @property
    def mean_freq(self):
        return numpy.mean([self[4].frequency_raw, self[6].frequency_raw])

    def export(self) -> Dict[str, float]:
        return {
            '4': self[4].frequency, '4_R2': self[4].r_squared,
            '6': self[6].frequency, '6_R2': self[6].r_squared,
            'diff': self.diff,
        }

    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return {'4', '6', '4_R2', '6_R2', 'diff'}
