import pathlib
from unittest import TestCase

from ipsiblings.config import AppConfig
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.property.frequency import FrequencyProperty
from ipsiblings.evaluation.property.norm_series import NormSeriesProperty
from ipsiblings.model import SiblingCandidate, Target
from ipsiblings.preparation.provider.filesystem import FilesystemProvider


def given_target() -> Target:
    conf = AppConfig()
    conf.paths.base_dir = pathlib.Path(__file__).parent
    provider = FilesystemProvider()
    provider.configure(conf)
    return provider.provide()['xxxx']


class TestFrequency(TestCase):
    def test_timestamps_to_series(self):
        # given
        timestamps = given_target().timestamps
        series = given_target().timestamps.as_series()
        # when
        equiv_tups = [(k, v) for (k, v) in series.data]
        # then
        self.assertEqual(equiv_tups, timestamps.timestamps)

    def test_clean_series(self):
        # given
        target = given_target()
        evaluated_sibling = EvaluatedSibling(SiblingCandidate(target, target))
        # when
        prop = evaluated_sibling.contribute_property_type(NormSeriesProperty)
        # then
        self.assertListEqual(
            list(prop[4].reception_times[:5]),
            [11.99898886680603, 27.997750520706177, 64.46249151229858, 66.46238923072815, 70.46224164962769]
        )
        self.assertListEqual(list(prop[4].ts_vals[:5]), [3000, 7000, 16117, 16617, 17617])

    def test_real_world_250(self):
        # given
        target = given_target()
        evaluated_sibling = EvaluatedSibling(SiblingCandidate(target, target))
        # when
        prop = evaluated_sibling.contribute_property_type(FrequencyProperty)
        # then
        self.assertEqual(prop[4].frequency, 250)
