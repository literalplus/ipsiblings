from typing import Optional, Tuple, Dict

import numpy

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingProperty
# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
from ipsiblings.evaluation.property.dynamic_range import DynamicRangeProperty
from ipsiblings.evaluation.property.offsets import OffsetSeries
from ipsiblings.evaluation.property.spline import SplineProperty, OffsetSpline


class SplineDiffProperty(SiblingProperty):
    """
    Maps the upper spline onto the lower one to make values comparable. Also subtracts the lower spline's value
    so that the mapped_diff array is relative to zero (i.e. 0 means that the mapped value is as expected).
    If no spline is present, all fields are None.
    Depends on SplineProperty and DynamicRangeProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'SplineDiffProperty':
        spline_prop = evaluated_sibling.contribute_property_type(SplineProperty)
        dynrange_prop = evaluated_sibling.contribute_property_type(DynamicRangeProperty)
        return cls(spline_prop[4], spline_prop[6], dynrange_prop.diff_absolute)

    def __init__(self, spline4: Optional[OffsetSpline], spline6: Optional[OffsetSpline], dynrange_diff: float):
        if spline4 and spline6:
            self.mapped_diff, diff_of_means_raw = self._map_upper_onto_lower(spline4, spline6)
            self.diff_of_means = abs(diff_of_means_raw)
            self.diff_scaled = diff_of_means_raw / dynrange_diff
            # NOTE: midpoint interpolation mimics the previous behaviour - 'linear' might be more meaningful
            self.diff_85_percentile = numpy.percentile(self.mapped_diff.offsets, q=85, interpolation='midpoint')
        else:
            self.mapped_diff, self.diff_of_means, self.diff_scaled = None, None, None

    def _map_upper_onto_lower(self, spline4: OffsetSpline, spline6: OffsetSpline) -> Tuple[OffsetSeries, float]:
        diff_of_means = spline4.mean - spline6.mean
        shared_length = min(len(spline4.data), len(spline6.data))
        upper_spline = spline4 if diff_of_means >= 0 else spline6
        lower_spline = spline6 if diff_of_means < 0 else spline4
        mapped_diffs = upper_spline.data[:shared_length].copy()
        mapped_diffs[OffsetSpline.KEY_OFFSET] = numpy.abs(
            (mapped_diffs[OffsetSpline.KEY_OFFSET] - abs(diff_of_means)) - lower_spline.offsets
        )
        return OffsetSeries(mapped_diffs), diff_of_means

    def export(self) -> Dict[str, float]:
        return {'pct85': self.diff_85_percentile}
