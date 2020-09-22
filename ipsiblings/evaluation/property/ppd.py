from typing import Tuple

import numpy

from ipsiblings import liblog, libconstants
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingProperty
from ipsiblings.evaluation.property.offsets import OffsetSeries
from ipsiblings.evaluation.property.outliers_mean import MeanOutlierRemovalProperty

# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew", GPLv2
# https://github.com/tumi8/siblings/

log = liblog.get_root_logger()


class PpdProperty(SiblingProperty):
    """
    Provides minimum Pairwise Point Distance for every IPv4 timestamp, relative to its closest IPv6 offset.
    Further computes 95.5% confidence interval thresholds around mean and median PPD.
    Depends on MeanOutlierRemovalProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'PpdProperty':
        mor_prop = evaluated_sibling.contribute_property_type(MeanOutlierRemovalProperty)
        return cls(mor_prop[4], mor_prop[6])

    def __init__(self, source4: OffsetSeries, source6: OffsetSeries):
        self.corresponding_v6_idxs = self._calc_closest_v6_ts_for_all_v4(source4, source6)
        self.ppd_by_v4_idx = self._calc_ppds_by_v4(self.corresponding_v6_idxs, source4, source6)
        min_offset = min(source4.offsets.min(initial=0), source6.offsets.min(initial=0))
        max_offset = max(source4.offsets.max(initial=0), source6.offsets.max(initial=0))
        self.offset_range = abs(min_offset - max_offset)
        self.ppd_mean_thresholds = self._calc_mean_thresholds(self.ppd_by_v4_idx)
        self.ppd_median_thresholds = self._calc_median_thresholds(self.ppd_by_v4_idx)

    def _calc_closest_v6_ts_for_all_v4(self, source4: OffsetSeries, source6: OffsetSeries) -> numpy.ndarray:
        smaller_input_len = min(len(source4.data), len(source6.data))
        closest_v6_idxs = numpy.zeros(smaller_input_len)
        for i in range(stop=smaller_input_len):
            current_v4_reception_ts = source4.reception_times[i]
            # This apparently might ValueError under mysterious circumstances - might want to handle that if possible
            closest_v6_idx = numpy.abs(source6.reception_times - current_v4_reception_ts).argmin()
            closest_v6_idxs[i] = closest_v6_idx
        return closest_v6_idxs

    def _calc_ppds_by_v4(
            self, corresponding_v6_idxs: numpy.ndarray, source4: OffsetSeries, source6: OffsetSeries
    ) -> numpy.ndarray:
        # Length is relevant for if one of the IPs stops responding
        smaller_input_len = min(len(source4.data), len(source6.data))
        ppds_by_v4 = numpy.zeros(smaller_input_len)
        for i4 in range(stop=smaller_input_len):
            offset4 = source4.offsets[i4]
            closest_offset6 = source6.offsets[corresponding_v6_idxs[i4]]
            ppds_by_v4[i4] = abs(offset4 - closest_offset6)
        return ppds_by_v4

    def _calc_mean_thresholds(self, ppds: numpy.ndarray) -> Tuple[float, float]:
        mean_ppd = numpy.mean(ppds)
        ppd_stdev = numpy.std(ppds)
        return (
            mean_ppd - libconstants.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * ppd_stdev,
            mean_ppd + libconstants.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * ppd_stdev,
        )

    def _calc_median_thresholds(self, ppds: numpy.ndarray) -> Tuple[float, float]:
        median_ppd = numpy.median(ppds)
        abs_deviations_from_median = numpy.abs(ppds - median_ppd)
        # https://en.wikipedia.org/wiki/Median_absolute_deviation#Relation_to_standard_deviation
        # NOTE: This assumes offsets to be normally distributed (which they are probably not)
        stdev_from_median = libconstants.SIB_CONSISTENCY_CONSTANT_K * numpy.median(abs_deviations_from_median)
        return (
            median_ppd - libconstants.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stdev_from_median,
            median_ppd + libconstants.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stdev_from_median
        )
