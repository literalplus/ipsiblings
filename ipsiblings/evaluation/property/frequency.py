# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
from typing import Dict, Set, Optional

import numpy
import scipy.stats as scipy_stats

from ipsiblings import logsetup
from ipsiblings.evaluation.model.property import FamilySpecificSiblingProperty, SiblingPropertyException
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.property.norm_series import NormTimestampSeries, NormSeriesProperty

log = logsetup.get_root_logger()


class FrequencyFailedException(SiblingPropertyException):
    pass


class FrequencyInfo:
    def __init__(self, clean_series: NormTimestampSeries):
        slope_raw, intercept, rval, pval, stderr = scipy_stats.linregress(
            clean_series.reception_times, clean_series.ts_vals
        )
        if numpy.isnan(slope_raw):
            raise FrequencyFailedException('Got NaN as slope from linregress')
        self.r_squared = rval * rval  # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
        self.frequency_raw = slope_raw
        # Kohno et al., p. 6, top right
        self.frequency = numpy.round(slope_raw, decimals=0)


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
        try:
            def provider(ip_version: int):
                return FrequencyInfo(clean_prop[ip_version])

            return cls(
                cls._cache_get_or(evaluated_sibling[4], provider),
                cls._cache_get_or(evaluated_sibling[6], provider)
            )
        except FrequencyFailedException as e:
            log.debug(f'Failed to compute frequency for {evaluated_sibling}', exc_info=e)

    def __init__(self, data4: FrequencyInfo, data6: FrequencyInfo):
        self.data4, self.data6 = data4, data6
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
