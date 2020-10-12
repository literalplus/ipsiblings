import ipaddress
from unittest import TestCase

from ipsiblings.btc.extra_net import CVersionPacket, CShortAddress
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.property.frequency import FrequencyProperty
from ipsiblings.evaluation.property.norm_series import NormSeriesProperty
from ipsiblings.model import SiblingCandidate


def hx(hex_str):
    return bytes.fromhex(hex_str)


class TestPackets(TestCase):
    def test_version_ser_example(self):  # https://developer.bitcoin.org/reference/p2p_networking.html#version
        # given
        pkt = CVersionPacket()
        pkt.version = 70002
        pkt.services = 0x01
        pkt.timestamp = 1415483324
        pkt.addr_recv = CShortAddress(0x01, ipaddress.IPv6Address(hx('00000000000000000000ffffc61b6409')), 0x208d)
        pkt.addr_trans = CShortAddress(0x01, ipaddress.IPv6Address(hx('00000000000000000000ffffcb0071c0')), 0x208d)
        pkt.nonce = 17893779652077781010
        pkt.user_agent_str = '/Satoshi:0.9.3/'
        pkt.start_height = 329167
        pkt.relay = True
        # when
        pkt.stream_serialize()
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
