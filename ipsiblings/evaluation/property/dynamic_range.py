from typing import Dict

import numpy

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, FamilySpecificSiblingProperty
from ipsiblings.evaluation.property.offsets import OffsetSeries
# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew", GPLv2
# https://github.com/tumi8/siblings
from ipsiblings.evaluation.property.ppd_outliers import PpdOutlierRemovalProperty
from ipsiblings.model import DataException


class DynamicRangeProperty(FamilySpecificSiblingProperty[float]):
    """
    Calculates dynamic range per address family and their average, difference and relative difference.
    The dynamic range results by pruning upper and lower 2.5% of indices and then computing
    the difference between the new extreme values.
    Depends on PpdOutlierRemovalProperty.
    """
    CUTOFF_FACTOR_LOW = 2.5 / 100.0
    CUTOFF_FACTOR_HIGH = 1.0 - CUTOFF_FACTOR_LOW

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'DynamicRangeProperty':
        ppd_outliers_prop = evaluated_sibling.contribute_property_type(PpdOutlierRemovalProperty)
        return cls(
            cls._calc_dynamic_range(ppd_outliers_prop[4]),
            cls._calc_dynamic_range(ppd_outliers_prop[6])
        )

    @classmethod
    def _calc_dynamic_range(cls, source: OffsetSeries):
        if not source.data:
            raise DataException("No source data for dynamic range - offsets empty?")
        sorted_offsets = numpy.sort(source.data, order=OffsetSeries.KEY_OFFSET)
        cutoff_idx_low = int(round(cls.CUTOFF_FACTOR_LOW * len(sorted_offsets)))
        cutoff_idx_high = int(round(cls.CUTOFF_FACTOR_HIGH * len(sorted_offsets)))
        new_min = sorted_offsets[cutoff_idx_low]
        new_max = sorted_offsets[cutoff_idx_high]
        return new_max - new_min

    def __init__(self, range4: float, range6: float):
        self.data4 = range4
        self.data6 = range6
        self.diff_absolute = abs(range4 - range6)
        self.average = numpy.mean([range4, range6])
        self.diff_relative = self.diff_absolute / self.average

    def export(self) -> Dict[str, float]:
        return {
            '4': self[4], '6': self[6],
            'diff_abs': self.diff_absolute,
            'diff_rel': self.diff_relative,
            'avg': self.average,
        }
