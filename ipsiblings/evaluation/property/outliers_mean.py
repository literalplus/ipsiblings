from typing import Dict, Set, Optional

import numpy

from ipsiblings import liblog, libconstants
from ipsiblings.evaluation.model.property import FamilySpecificSiblingProperty
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.property.denoise import DenoiseProperty
from ipsiblings.evaluation.property.offsets import OffsetSeries

# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew", GPLv2
# https://github.com/tumi8/siblings/blob/140418dca0547a08b12c01e8df1b514c4f2f25c2/src/sibling_decision.py#L561


log = liblog.get_root_logger()


class MeanOutlierRemovalProperty(FamilySpecificSiblingProperty[OffsetSeries]):
    """
    Filters denoised timestamps such that only a 97% confidence interval around the mean is retained.
    Depends on DenoiseProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'Optional[MeanOutlierRemovalProperty]':
        denoise_prop = evaluated_sibling.contribute_property_type(DenoiseProperty)
        if not denoise_prop:
            return None
        cleaned4, cleaned6 = cls._remove_outliers_97(denoise_prop[4]), cls._remove_outliers_97(denoise_prop[6])
        if not cleaned4.has_data() or not cleaned6.has_data():
            return None
        return cls(cleaned4, cleaned6)

    @classmethod
    def _remove_outliers_97(cls, source: OffsetSeries) -> OffsetSeries:
        with numpy.errstate(invalid='raise'):
            try:
                mean = numpy.mean(source.offsets)
                stddev = numpy.std(source.offsets)  # may raise numpy warning for malformed array - when?
            except Exception:
                log.exception(f'numpy warning during outlier-mean for {source.offsets}')
                return source
        thresh_low, thresh_high = (
            mean - libconstants.SIB_Z_SCORE_CONFIDENCE_LEVEL_97 * stddev,
            mean + libconstants.SIB_Z_SCORE_CONFIDENCE_LEVEL_97 * stddev
        )
        raw_data = source.data[numpy.where(numpy.logical_and(
            thresh_low <= source.offsets, source.offsets <= thresh_high
        ))]
        return OffsetSeries(raw_data)

    def __init__(self, filtered4: OffsetSeries, filtered6: OffsetSeries):
        self.data4 = filtered4
        self.data6 = filtered6

    def export(self) -> Dict[str, int]:
        return {'len4': len(self[4]), 'len6': len(self[6])}

    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return {'len4', 'len6'}
