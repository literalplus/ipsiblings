from typing import Tuple, Dict, Set, Optional

import numpy
from scipy.stats import mstats as scipy_mstats
from scipy.stats import stats as scipy_stats

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingProperty
from ipsiblings.evaluation.property.offsets import OffsetSeries
from ipsiblings.evaluation.property.ppd_outliers import PpdOutlierRemovalProperty


# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew", GPLv2
# https://github.com/tumi8/siblings


class SkewProperty(SiblingProperty):
    """
    Calculates a skew estimation per address family using linear regression.
    The skew4/6 values contain alpha, the slope of the skew estimation.
    Provides difference, R^2 and difference between R^2 values.
    Further provides the angle between the two skew estimations.
    Depends on PpdOutlierRemovalProperty.
    """
    CUTOFF_FACTOR_LOW = 2.5 / 100.0
    CUTOFF_FACTOR_HIGH = 1.0 - CUTOFF_FACTOR_LOW

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'Optional[SkewProperty]':
        ppd_outliers_prop = evaluated_sibling.contribute_property_type(PpdOutlierRemovalProperty)
        if not ppd_outliers_prop:
            return None
        return cls(
            cls._calc_skew_angle(ppd_outliers_prop[4]),
            cls._calc_skew_angle(ppd_outliers_prop[6])
        )

    @classmethod
    def _calc_skew_angle(cls, source: OffsetSeries) -> Tuple[float, float]:
        # We use ordinary linear regression just for the R^2 value (below function does not provide it)
        _, _, rval, _, _ = scipy_stats.linregress(source.reception_times, source.offsets)
        # Apply robust linear regression - note that (x, y) is flipped in the argument list
        medslope, _, _, _ = scipy_mstats.theilslopes(source.offsets, source.reception_times)
        return medslope, rval ** 2

    def __init__(self, skew4: Tuple[float, float], skew6: Tuple[float, float]):
        self.skew4, self.r_square4 = skew4
        self.skew6, self.r_square6 = skew6
        self.skew_diff = abs(self.skew4 - self.skew6)
        self.r_square_diff = abs(self.r_square4 - self.r_square6)
        theta_tmp = (self.skew4 - self.skew6) / (1 + self.skew4 * self.skew6)
        self.skew_diff_angle_rad = numpy.arctan(abs(theta_tmp))

    def __getitem__(self, item) -> float:
        if item == 4:
            return self.skew4
        elif item == 6:
            return self.skew6
        else:
            raise KeyError

    def export(self) -> Dict[str, float]:
        return {
            '4': self[4], '6': self[6],
            '4_R2': self.r_square4, '6_R2': self.r_square6,
            'diff': self.skew_diff,
            'R2_diff': self.r_square_diff,
            'theta': self.skew_diff_angle_rad,
        }

    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return {
            '4', '6', '4_R2', '6_R2',
            'diff', 'R2_diff', 'theta'
        }
