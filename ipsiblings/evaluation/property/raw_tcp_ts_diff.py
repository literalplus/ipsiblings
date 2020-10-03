# The code in this file is based on the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
from typing import Dict, Set, Optional

from ipsiblings.evaluation.model.property import SiblingProperty
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.property.frequency import FrequencyProperty


class FirstTimestampDiffProperty(SiblingProperty):
    """
    Converts the first TSval timestamps to seconds and computes the difference between IPv4 and IPv6 trace.
    This is then compared to the difference in reception timestamps.
    The provided value is how far these differences are apart (absolute).
    Often referred to as Delta-tcp-raw.
    Depends on FrequencyProperty.
    """

    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'Optional[FirstTimestampDiffProperty]':
        freq_prop = evaluated_sibling.contribute_property_type(FrequencyProperty)
        if not freq_prop:
            return None
        # Convert to Python int to prevent overflow. lol
        tsval_diff = (int(evaluated_sibling[4].first_ts_val) - int(evaluated_sibling[6].first_ts_val))
        tcp_diff_secs = tsval_diff / freq_prop.mean_freq
        recv_time_diff_secs = evaluated_sibling[4].first_reception_time - evaluated_sibling[6].first_reception_time
        return cls(tcp_diff_secs, recv_time_diff_secs)

    def __init__(self, tcp_diff_secs, recv_time_diff_secs):
        self.raw_timestamp_diff = abs(tcp_diff_secs - recv_time_diff_secs)

    def export(self) -> Dict[str, float]:
        return {'raw_ts_diff': self.raw_timestamp_diff}

    @classmethod
    def get_export_keys(cls) -> Set[str]:
        return {'raw_ts_diff'}
