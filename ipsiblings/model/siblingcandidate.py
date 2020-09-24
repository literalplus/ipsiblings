# libsiblings/siblingcandidate.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

from typing import Dict, Optional

import numpy

from .target import Target
from .tcpopts import TcpOptions
from .timestampseries import TimestampSeries
from .. import libconstants as const
from .. import liblog

log = liblog.get_root_logger()


# TODO: This class absolutely needs to be split, at least the evaluation logic!


class SiblingCandidate(object):
    """
    Represents a concrete SiblingCandidate.
    """

    TS_DIFF_THRESHOLD = 0.305211037  # ours; Scheitle at al. use 0.2557

    def __init__(
            self, target4: Target, target6: Target
    ):
        # TODO: Reduce v4/v6 duplication by splitting data into two objects like with Target
        self.series: Dict[int, TimestampSeries] = {
            4: TimestampSeries.of_ts(target4.timestamps),
            6: TimestampSeries.of_ts(target6.timestamps),
        }
        self.tcp_options: Dict[int, Optional[TcpOptions]] = {
            4: target4.tcp_options,
            6: target6.tcp_options,
        }

        # BELOW: old API
        self.sibling_status = const.SIB_STATUS_UNKNOWN
        self.calc_finished = False  # flag to check if calculations have finished (due to error or valid result)
        self.is_sibling = False
        self.calc_error = False  # flag to check if exception occurred -> correct status assignment

        self.ip4, self.port4 = target4.address, target4.port
        self.ip6, self.port6 = target6.address, target6.port
        self.ip4_tcpopts, self.ip6_tcpopts = target4.tcp_options.data, target6.tcp_options.data
        self.domains = target4.domains + target6.domains

        dt = numpy.dtype('int64, float64')  # data type for numpy array
        columns = ['remote', 'received']  # column/index name -> e.g. access with ip4_ts['remote']
        dt.names = columns

        self.ip4_ts = numpy.array(target4.timestamps.timestamps, dtype=dt)
        self.ip6_ts = numpy.array(target4.timestamps.timestamps, dtype=dt)
        self.recv_offset4 = self.ip4_ts['received'][0]  # timestamp data e.g. 1541886109.485699 (float)
        self.recv_offset6 = self.ip6_ts['received'][0]
        self.tcp_offset4 = self.ip4_ts['remote'][0]  # timestamp data e.g. 1541886109 (uint32)
        self.tcp_offset6 = self.ip6_ts['remote'][0]

        self.tcp_opts_differ = self.calc_tcp_opts_differ()  # if None, no tcp options are available -> ignore

        self.ssh_available = False  # TODO: We need a new concept to determine if we have SSH
        self.ssh_keys_match = None  # TODO: SSH keys used to be taken as parameters
        self.ssh4 = {}
        self.ssh6 = {}

        self.agent4 = ''
        self.agent6 = ''
        self.ssh_agents_match = None

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, other):
        if isinstance(other, SiblingCandidate):
            return self.key == other.key
        return NotImplemented

    def __str__(self):
        p4_str = '({0})'.format(self.port4)
        p6_str = '({0})'.format(self.port6)
        return f'SiblingCandidate - {self.ip4:<15} {p4_str:>7}   <=>   {p6_str:<7} {self.ip6:<39}'

    @property
    def key(self):
        return self.ip4, self.port4, self.ip6, self.port6

    def has_ssh(self):
        # TODO: Currently defunct, see note in constructor (if it's gone, this comment is probably obsolete)
        return self.ssh_available

    def addsshkey(self, type, key, version):
        if version == const.IP4:
            self.ssh4[type] = key
        elif version == const.IP6:
            self.ssh6[type] = key

    def addsshkeys(self, keys, version):
        if version == const.IP4:
            self.ssh4 = keys  # { type: key }
        elif version == const.IP6:
            self.ssh6 = keys  # { type: key }
        else:
            return

        if self.ssh4 and self.ssh6:  # check matching keys if both ssh key values set
            self.ssh_keys_match = self.keys_match()

    def keys_match(self):
        if not self.ssh4 or not self.ssh6:
            return None

        keytypes = set(self.ssh4.keys()).intersection(set(self.ssh6.keys()))

        if not keytypes:
            return None

        for type in keytypes:
            if self.ssh4[type] != self.ssh6[type]:
                return False

        return True

    def addsshagent(self, agent, version):
        if version == const.IP4:
            self.agent4 = agent.strip()
        elif version == const.IP6:
            self.agent6 = agent.strip()
        else:
            return None

        self.ssh_agents_match = self.agents_match()

    def agents_match(self):
        if not self.agent4 or not self.agent6:
            return None
        return self.agent4 == self.agent6

    def get_status(self):
        """
        -> (calculations_finished, sibling_status)
        """
        return self.calc_finished, self.sibling_status

    def get_features(self, key_list=None, substitute_none=None):
        """
        Return features used for machine learning.
        """
        if key_list:
            keys = key_list
        else:
            keys = ['hz4', 'hz6', 'hz_diff', 'hz4_R2', 'hz6_R2', 'hz_rsqrdiff', 'raw_timestamp_diff', 'alpha4',
                    'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'dynrange4', 'dynrange6', 'dynrange_diff',
                    'dynrange_avg', 'dynrange_diff_rel', 'spl_diff', 'spl_diff_scaled', 'ssh_keys_match',
                    'ssh_agents_match', 'geoloc_diff']

        features = {}
        for key in keys:
            features[key] = getattr(self, key, substitute_none)
        return features

    def calc_tcp_opts_differ(self):
        # e.g. [('MSS', 1360), ('NOP', None), ('NOP', None), ('Timestamp', (453053021, 1337)), ('NOP', None), ('WScale', 8)]
        # Paper TCP options format: 'MSS-SACK-TS-N-WS03-'
        # MSS -> Max Segment Size; SACK -> Selective ACK, TS -> TimeStamp, N -> Nop, WS03 -> WindowScale factor 3
        # CHECK: presence, option order, nop padding bytes, window scale value (if present)

        if not all([self.ip4_tcpopts, self.ip6_tcpopts]):
            return None

        opt4 = iter(self.ip4_tcpopts)
        opt6 = iter(self.ip6_tcpopts)

        while True:
            o4 = next(opt4, None)
            o6 = next(opt6, None)

            if not o4 and not o6:
                return False  # options matched until now -> finished

            if o4 and not o6:
                log.debug('Missing TCP option in IPv6: {0}'.format(o4[0]))
                return True
            if not o4 and o6:
                log.debug('Missing TCP option in IPv4: {0}'.format(o6[0]))
                return True

            if o4[0] != o6[0]:
                log.debug('TCP options are ordered differently - IPv4: {0} / IPv6: {1}'.format(o4[0], o6[0]))
                return True

            if o4[0] == 'WScale':  # at this point we can be sure that ip6 as well as ip4 options are the same
                if o4[1] != o6[1]:
                    log.debug('Window Scale option factor does not match - IPv4: {0} / IPv6: {1}'.format(o4[1], o6[1]))
                    return True
