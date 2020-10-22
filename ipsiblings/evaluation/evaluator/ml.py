import pathlib
from typing import List, Any, Dict

import numpy
import pandas
import xgboost

from ipsiblings import liblog
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.evaluator.tcpraw import StarkeTcprawEvaluator
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.evaluation.property.dynamic_range import DynamicRangeProperty
from ipsiblings.evaluation.property.frequency import FrequencyProperty
from ipsiblings.evaluation.property.raw_tcp_ts_diff import FirstTimestampDiffProperty
from ipsiblings.evaluation.property.skew import SkewProperty
from ipsiblings.model import const

log = liblog.get_root_logger()


class MachineLearningEvaluator(SiblingEvaluator):
    """
    Evaluates based on the Machine Learning model proposed by Starke for randomised offsets.
    """
    # Keys taken from old evaluation.py, feature_keys['no_raw']. Order is crucial!
    _FEATURE_KEYS = [
        'hz_diff', 'hz_rsqrdiff',
        'alphadiff', 'rsqrdiff',
        'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel',
    ]

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        return cls()

    def __init__(self):
        super().__init__(const.EvaluatorChoice.ML_STARKE)
        model_path = pathlib.Path(__file__).parent.parent.parent / 'assets' / 'model_FRT_no-rawts-new.native.bin'
        self.classifier = xgboost.XGBClassifier()
        booster = xgboost.Booster()
        booster.load_model(model_path)
        # ref: https://github.com/dmlc/xgboost/issues/706#issuecomment-167253974
        self.classifier._Booster = booster

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        first_ts_prop = evaluated_sibling.contribute_property_type(FirstTimestampDiffProperty)
        if first_ts_prop and first_ts_prop.raw_timestamp_diff <= StarkeTcprawEvaluator.THRESHOLD:
            # The no-rawts ML model we are using is not supposed to be applied to
            # sibling candidates that already match the Delta-tcpraw criterion
            return SiblingStatus.INDECISIVE
        only_row = self._features_from_evaluated(evaluated_sibling)
        if not only_row:
            return SiblingStatus.ERROR
        data = pandas.DataFrame([only_row], columns=self._FEATURE_KEYS)
        results = self.classifier.predict(data)
        if results[0]:
            return SiblingStatus.POSITIVE
        else:
            return SiblingStatus.NEGATIVE

    def _features_from_evaluated(self, evaluated_sibling: EvaluatedSibling) -> Dict[str, Any]:
        # Keys taken from old evaluation.py, feature_keys['no_raw']. Order is crucial!
        # Features are defined on in Starke p. 69, Table 4.4
        # we are using the no-rawts model (the only one provided as raw data),
        # note that this is not supposed to apply to constant-offset candidates that already
        # match the Delta-tcpraw criterion.
        freq = evaluated_sibling.contribute_property_type(FrequencyProperty)
        skew = evaluated_sibling.contribute_property_type(SkewProperty)
        dyn_range = evaluated_sibling.contribute_property_type(DynamicRangeProperty)
        if not freq or not skew or not dyn_range:
            return {}
        features = {
            'hz_diff': freq.diff,
            'hz_rsqrdiff': freq.r_squared_diff,
            'alphadiff': skew.skew_diff,
            'rsqrdiff': skew.r_square_diff,
            'dynrange_diff': dyn_range.diff_absolute,
            'dynrange_avg': dyn_range.average,
            'dynrange_diff_rel': dyn_range.diff_relative,
        }
        for key, value in features.items():
            if not value:
                features[key] = numpy.nan
        return features
