from typing import List, Optional, Dict, Set

import numpy
from numpy.lib import recfunctions
from scipy import interpolate as scipy_interpolate

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, FamilySpecificSiblingProperty
# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
from ipsiblings.evaluation.property.offsets import OffsetSeries
from ipsiblings.evaluation.property.ppd_outliers import PpdOutlierRemovalProperty


class OffsetSpline(OffsetSeries):
    _BIN_COUNT = 12
    _VALUE_CUTOFF_BOTH_SIDES = 8
    _X_SPACING = 120  # space between x-values to compute spline values for
    _SPLINE_DEGREE = 3

    def __init__(self, offset_data: numpy.ndarray, internal_knots: List[float], x_values: numpy.ndarray):
        self.spline_obj = scipy_interpolate.LSQUnivariateSpline(
            x=offset_data[self.KEY_RECEPTION_TIME], y=offset_data[self.KEY_OFFSET],
            t=internal_knots,
            bbox=[None, None],  # bounding box
            k=self._SPLINE_DEGREE
        )
        unstructured_data = numpy.array([x_values, self.spline_obj(x_values)]).T
        structured_data = recfunctions.unstructured_to_structured(unstructured_data, dtype=self.DTYPE)
        super(OffsetSpline, self).__init__(structured_data)
        self.mean = numpy.mean(self.offsets)

    @classmethod
    def from_offsets(cls, source: OffsetSeries) -> Optional['OffsetSpline']:
        try:
            bin_width = cls._calc_equidistant_bin_width(source)
            relevant_data = source.data[cls._VALUE_CUTOFF_BOTH_SIDES:-cls._VALUE_CUTOFF_BOTH_SIDES]
            first_time = relevant_data[cls.KEY_RECEPTION_TIME][0]
            last_time = relevant_data[cls.KEY_RECEPTION_TIME][-1]
            x_values = numpy.arange(first_time, last_time, cls._X_SPACING)
            all_knots = [first_time + i * bin_width for i in range(1, cls._BIN_COUNT)]
            internal_knots = all_knots[1:-1]
        except KeyError:
            return None
        return cls(relevant_data, internal_knots, x_values)

    @classmethod
    def _calc_equidistant_bin_width(cls, source: OffsetSeries):
        first_time = source.reception_times[0]
        last_time = source.reception_times[-1]
        return round((last_time - first_time) / cls._BIN_COUNT, 1)


class SplineProperty(FamilySpecificSiblingProperty[Optional[OffsetSpline]]):
    """
    Interpolates a univariate spline with knots of fixed distance over outlier-removed offset series.
    This strips the lower and upper eight values and hence might not always be available.
    Depends on PpdOutlierRemovalProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'SplineProperty':
        clean_prop = evaluated_sibling.contribute_property_type(PpdOutlierRemovalProperty)
        return cls(
            OffsetSpline.from_offsets(clean_prop[4]),
            OffsetSpline.from_offsets(clean_prop[6]),
        )

    def __init__(self, spline4: Optional[OffsetSpline], spline6: Optional[OffsetSpline]):
        self.data4 = spline4
        self.data6 = spline6

    def export(self) -> Dict[str, str]:
        return {}

    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return set()
