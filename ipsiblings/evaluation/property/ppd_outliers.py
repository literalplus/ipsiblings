from typing import Dict

import numpy

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, FamilySpecificSiblingProperty
from ipsiblings.evaluation.property.offsets import OffsetSeries
from ipsiblings.evaluation.property.outliers_mean import MeanOutlierRemovalProperty
from ipsiblings.evaluation.property.ppd import PpdProperty


# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew", GPLv2
# https://github.com/tumi8/siblings


class PpdOutlierRemovalProperty(FamilySpecificSiblingProperty[OffsetSeries]):
    """
    Filters denoised timestamps such that only a 97% confidence interval around the mean is retained.
    Depends on PpdProperty and MeanOutlierRemovalProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'PpdOutlierRemovalProperty':
        ppd_prop = evaluated_sibling.contribute_property_type(PpdProperty)
        mean_outliers_prop = evaluated_sibling.contribute_property_type(MeanOutlierRemovalProperty)
        return cls(mean_outliers_prop[4], mean_outliers_prop[6], ppd_prop)

    def __init__(self, filtered4: OffsetSeries, filtered6: OffsetSeries, ppd_prop: PpdProperty):
        # If this ever becomes public API, convert it to a proper structured array for semantic access
        remaining_ppds_indexed = self.filter_ppds_with_indices(ppd_prop.ppd_median_thresholds, ppd_prop.ppd_by_v4_idx)
        self.new_ppd_range = max(remaining_ppds_indexed) - min(remaining_ppds_indexed)

        raw_data4 = numpy.zeros(len(remaining_ppds_indexed), dtype=OffsetSeries.DTYPE)
        raw_data6 = numpy.zeros(len(remaining_ppds_indexed), dtype=OffsetSeries.DTYPE)
        for result_idx, (v4index, ppd) in enumerate(remaining_ppds_indexed):
            raw_data4[result_idx] = filtered4.data[v4index]
            raw_data6[result_idx] = filtered6.data[ppd_prop.corresponding_v6_idxs[v4index]]

        self.data4 = OffsetSeries(raw_data4)
        self.data6 = OffsetSeries(raw_data6)

    def filter_ppds_with_indices(self, thresholds, ppds: numpy.ndarray) -> numpy.ndarray:
        thresh_low, thresh_high = thresholds
        ppds_indexed = self._stack_with_indices(ppds).T
        remaining_ppds_indexed = ppds_indexed[numpy.where(numpy.logical_and(
            thresh_low <= ppds, ppds <= thresh_high
        ))]
        return remaining_ppds_indexed

    def _stack_with_indices(self, arr: numpy.ndarray) -> numpy.ndarray:
        return numpy.stack([numpy.arange(len(arr)), arr])

    def export(self) -> Dict[str, float]:
        return {'ppd_rng': self.new_ppd_range}
