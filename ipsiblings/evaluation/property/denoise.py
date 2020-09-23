from typing import List, Dict

import numpy

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, FamilySpecificSiblingProperty
from ipsiblings.evaluation.property.offsets import OffsetSeries, OffsetsProperty

# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew", GPLv2
# -> https://github.com/tumi8/siblings/blob/140418dca0547a08b12c01e8df1b514c4f2f25c2/src/sibling_decision.py#L425

WINDOW_SIZE_SECONDS = 120


class DenoiseProperty(FamilySpecificSiblingProperty[OffsetSeries]):
    """
    Provides denoised offset series, such that for every window of size WINDOW_SIZE_SECONDS,
    exactly one offset is retained, and that is the minimum offset in that window.
    Depends on OffsetsProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'DenoiseProperty':
        offset_prop = evaluated_sibling.contribute_property_type(OffsetsProperty)
        return cls(cls._denoise(offset_prop[4]), cls._denoise(offset_prop[6]))

    @classmethod
    def _denoise(cls, source: OffsetSeries):
        # NOTE: This assumes that reception timestamps are monotone increasing,
        # otherwise a new hour will be created for any late arrivals
        reception_windows = numpy.floor(source.reception_times / WINDOW_SIZE_SECONDS)
        window_item_counts = numpy.unique(reception_windows, return_counts=True)[1]
        window_end_indices = numpy.cumsum(window_item_counts)[:-1]  # remove last to avoid empty array at end
        data_per_window: List[numpy.ndarray] = numpy.split(source.data, window_end_indices)

        def min_reception_time_of_array(window_data: numpy.ndarray):
            return min(window_data, key=lambda tup: tup[OffsetSeries.KEY_RECEPTION_TIME])

        window_minima_lst = list(map(min_reception_time_of_array, data_per_window))  # list of tuples (rcv, min_offset)
        window_minima = numpy.array(window_minima_lst, dtype=OffsetSeries.DTYPE)
        return OffsetSeries(window_minima)

    def __init__(self, denoised4: OffsetSeries, denoised6: OffsetSeries):
        self.data4 = denoised4
        self.data6 = denoised6

    def export(self) -> Dict[str, int]:
        return {'len4': len(self[4]), 'len6': len(self[6])}
