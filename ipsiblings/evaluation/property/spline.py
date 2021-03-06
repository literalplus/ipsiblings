from typing import List, Optional, Dict, Set

import numpy
from numpy.lib import recfunctions
from scipy import interpolate as scipy_interpolate

from ipsiblings import logsetup
from ipsiblings.evaluation.model.property import FamilySpecificSiblingProperty
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.property.offsets import OffsetSeries
from ipsiblings.evaluation.property.ppd_outliers import PpdOutlierRemovalProperty

# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)


log = logsetup.get_root_logger()


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
            relevant_data = source.data[cls._VALUE_CUTOFF_BOTH_SIDES:-cls._VALUE_CUTOFF_BOTH_SIDES]
            if len(relevant_data) <= cls._BIN_COUNT:
                return None
            bin_width = cls._calc_equidistant_bin_width(relevant_data)
            first_time = relevant_data[cls.KEY_RECEPTION_TIME][0]
            last_time = relevant_data[cls.KEY_RECEPTION_TIME][-1]
            x_values = numpy.arange(first_time, last_time, cls._X_SPACING)
            all_knots = [first_time + i * bin_width for i in range(1, cls._BIN_COUNT)]
            internal_knots = all_knots[1:-1]
        except KeyError:
            log.debug(f'Spline: KeyError')
            return None
        except ValueError as e:
            if "The input parameters have been rejected by fpchec" in repr(e):
                log.debug(f'Spline parameters rejected')
                return None
            else:
                raise e
        return cls(relevant_data, internal_knots, x_values)

    @classmethod
    def _calc_equidistant_bin_width(cls, source: numpy.ndarray):
        first_time = source[cls.KEY_RECEPTION_TIME][0]
        last_time = source[cls.KEY_RECEPTION_TIME][-1]
        return round((last_time - first_time) / cls._BIN_COUNT, 6)


class SplineProperty(FamilySpecificSiblingProperty[OffsetSpline]):
    """
    Interpolates a univariate spline with knots of fixed distance over outlier-removed offset series.
    This strips the lower and upper eight values and hence might not always be available.
    Depends on PpdOutlierRemovalProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'Optional[SplineProperty]':
        clean_prop = evaluated_sibling.contribute_property_type(PpdOutlierRemovalProperty)
        if not clean_prop:
            return None
        # Cannot cache because we depend on PpdOutlierRemovalProperty,
        # which uses both series
        spline4 = OffsetSpline.from_offsets(clean_prop[4])
        spline6 = OffsetSpline.from_offsets(clean_prop[6])
        if not spline4 or not spline6 or not spline4.has_data() or not spline6.has_data():
            return None
        return cls(spline4, spline6)

    def __init__(self, spline4: OffsetSpline, spline6: OffsetSpline):
        self.data4 = spline4
        self.data6 = spline6

    def export(self) -> Dict[str, str]:
        return {}

    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return set()
