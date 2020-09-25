# libsiblings/lowrtsiblingcandidate.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

import numpy
from scipy import interpolate
from scipy import stats

from .exception import SiblingEvaluationError
from .siblingcandidate import SiblingCandidate
from .target import Target
from .. import libconstants as const
from .. import liblog

log = liblog.get_root_logger()


class LowRTSiblingCandidate(SiblingCandidate):

    def __init__(
            self, target4: Target, target6: Target
    ):
        # Limit the number of timestamps with nr_timestamps to have all candidates
        # the same amount of timestamps for evaluation
        # TODO: ^ We had this concept before, might need it again
        # NOTE: This class previously duplicated the constructor of super
        super().__init__(target4, target6)

        self.number_of_timestamps = min(len(self.ip4_ts), len(self.ip6_ts))

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

        features = super().get_features(key_list=keys, substitute_none=substitute_none)

        if not const.SIB_LOWRT_CALC_SPLINE or self.number_of_timestamps < const.SIB_LOWRT_MIN_TIMESTAMPS_FULL_CALC:
            try:
                del (features['spl_diff'])
                del (features['spl_diff_scaled'])
            except:
                pass

        if not const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES:  # or self.number_of_timestamps < const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES_MIN_TIMESTAMPS:
            keys = ['alpha4', 'alpha6', 'alphadiff', 'rsqr4', 'rsqr6', 'rsqrdiff', 'dynrange4', 'dynrange6',
                    'dynrange_diff', 'dynrange_avg', 'dynrange_diff_rel']
            for key in keys:
                try:
                    del (features[key])
                except:
                    continue

        return features

    def _calc_frequency(self, ipversion=None):
        # TODO: how is this different from super's impl?
        if ipversion == 4:
            recv_ts = self.ip4_ts['received']
            tcp_ts = self.ip4_ts['remote']
            offset_recv = self.recv_offset4
            offset_tcp = self.tcp_offset4
        elif ipversion == 6:
            recv_ts = self.ip6_ts['received']
            tcp_ts = self.ip6_ts['remote']
            offset_recv = self.recv_offset6
            offset_tcp = self.tcp_offset6
        else:  # should never happen
            return None, None, None, None, None

        nr_timestamps = len(recv_ts)  # already identical length

        if nr_timestamps <= 2:  # if we only have <= 2 timestamps available
            if not nr_timestamps > 0:
                log.error('IPv{0}: not enough timestamps available - {1} / {2}'.format(ipversion, self.ip4, self.ip6))
                return None, None, None, None, None

            tcp_diff = tcp_ts[1] - offset_tcp
            if tcp_diff == 0:
                log.error('IPv{0}: received identical remote timestamps, linregress not possible for {1} / {2}'.format(
                    ipversion, self.ip4, self.ip6))
                return None, None, None, None, None

            # do linreg with offset value and the only timestamp in the array
            Xi_arr = numpy.array([0, recv_ts[1] - offset_recv])
            Vi_arr = numpy.array([0, tcp_diff])

            slope_raw, intercept, rval, pval, stderr = stats.linregress(Xi_arr, Vi_arr)
            hz_R2 = rval * rval  # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
            hz = int(
                const.SIB_FREQ_ROUND_BASE * round(slope_raw / const.SIB_FREQ_ROUND_BASE))  # Kohno et al. Section 4.3

            return hz, Xi_arr, Vi_arr, hz_R2, slope_raw

        else:

            Xi_arr = numpy.zeros(nr_timestamps - 1)
            Vi_arr = numpy.zeros(nr_timestamps - 1)

            adjustment_recv = 0
            adjustment_tcp = 0
            for i in range(1, nr_timestamps):

                # in doubt, also do this for packet receive timestamps
                if recv_ts[i] + const.SIB_TS_OVERFLOW_THRESHOLD < recv_ts[i - 1]:
                    if recv_ts[i - 1] > 2 ** 31:
                        adjustment_recv = 2 ** 32
                xi = recv_ts[i] + adjustment_recv - offset_recv

                if tcp_ts[i] + const.SIB_TS_OVERFLOW_THRESHOLD < tcp_ts[i - 1]:
                    if tcp_ts[i - 1] > 2 ** 31:
                        adjustment_tcp = 2 ** 32
                vi = tcp_ts[i] + adjustment_tcp - offset_tcp

                Xi_arr[i - 1] = xi
                Vi_arr[i - 1] = vi

            # We remove duplicates at low runtime because they may influence the rval**2
            # which in turn results in classification as incorrect clock rate
            # This does not touch the required monotonocity -> rval**2 will be very low
            # if timestamps are randomized
            ##########################################################################
            # https://stackoverflow.com/a/10996196
            diff = numpy.diff(Vi_arr)
            indices = []
            for i, val in enumerate(diff):
                if val == 0:
                    indices.append(i)

            # if len(indices) >= int(len(Vi_arr) * const.SIB_TS_MONOTONICITY_PERCENTAGE):
            #   log.error('IPv{0} error: more than {1}% of timestamps to be removed for strict monotonicity!'.format(ipversion, int(const.SIB_TS_MONOTONICITY_PERCENTAGE * 100)))
            #   return (None, None, None, None, None)

            Xi_arr = numpy.delete(Xi_arr, indices)  # remove duplicate timestamps
            Vi_arr = numpy.delete(Vi_arr, indices)  # -> few timestamps should not have duplicates

            if len(Vi_arr) > 1:
                pass  # We do not check for monotonicity -> check rval**2 instead (few timestamps )
                # numpy.all(numpy.diff(Vi_arr) >= 0) # probably more elegant way but returns new array with diffs (slicing only uses array views (twice as fast!))
                # if not numpy.all(Vi_arr[1:] >= Vi_arr[:-1]): # non-monotonic after adjustment -> probably randomized timestamps
                #   return (None, None, None, None, None)
            elif len(Vi_arr) > 0:
                tcp_diff = tcp_ts[0] - offset_tcp
                if tcp_diff == 0:
                    log.error(
                        'IPv{0}: only identical remote timestamps after removing duplicates available, linregress not possible for {1} / {2}'.format(
                            ipversion, self.ip4, self.ip6))
                    return (None, None, None, None, None)

                # do linreg with offset value and the only timestamp in the array
                Xi_arr = numpy.array([0, recv_ts[0] - offset_recv])
                Vi_arr = numpy.array([0, tcp_diff])
            elif len(Vi_arr) <= 0:  # should probably never happen
                log.error(
                    'IPv{0}: not enough timestamps available after removing duplicates - {1} / {2}'.format(ipversion,
                                                                                                           self.ip4,
                                                                                                           self.ip6))
                return (None, None, None, None, None)

            # perform regression
            slope_raw, intercept, rval, pval, stderr = stats.linregress(Xi_arr, Vi_arr)
            hz_R2 = rval * rval  # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
            hz = int(
                const.SIB_FREQ_ROUND_BASE * round(slope_raw / const.SIB_FREQ_ROUND_BASE))  # Kohno et al. Section 4.3

            return (hz, Xi_arr, Vi_arr, hz_R2, slope_raw)

    def calc_frequency(self):
        # TODO: how is this different from super's impl?
        hz4, Xi4, Vi4, hz4_R2, hz4_raw = self._calc_frequency(ipversion=4)
        hz6, Xi6, Vi6, hz6_R2, hz6_raw = self._calc_frequency(ipversion=6)

        # DO NOT DECIDE HERE -> just plain calculations
        # if abs(hz4_raw) < const.SIB_FREQ_IP4_MIN and abs(hz6_raw) < const.SIB_FREQ_IP6_MIN:
        #   self.sibling_status = const.SIB_STATUS_ALL_FREQ_TOO_LOW
        #   log.error('Both IPs frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
        #   return False
        # if abs(hz4_raw) < const.SIB_FREQ_IP4_MIN:
        #   self.sibling_status = const.SIB_STATUS_IP4_FREQ_TOO_LOW
        #   log.error('IPv4 - frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
        #   return False
        # if abs(hz6_raw) < const.SIB_FREQ_IP6_MIN:
        #   self.sibling_status = const.SIB_STATUS_IP6_FREQ_TOO_LOW
        #   log.error('IPv6 - frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
        #   return False
        #
        # if hz4_R2 < const.SIB_FREQ_IP4_R2_MIN_LOWRT and hz6_R2 < const.SIB_FREQ_IP6_R2_MIN_LOWRT:
        #   self.sibling_status = const.SIB_STATUS_ALL_R2_TOO_LOW
        #   log.error('Both IPs r-squared below defined threshold - maybe randomized TS ({0} / {1}): {2} / {3}'.format(hz4_R2, hz6_R2, self.ip4, self.ip6))
        #   return False
        # if hz4_R2 < const.SIB_FREQ_IP4_R2_MIN_LOWRT:
        #   self.sibling_status = const.SIB_STATUS_IP4_R2_TOO_LOW
        #   log.error('IPv4 - r-squared below defined threshold (< {0}) - maybe randomized TS: {1} / {2}'.format(const.SIB_FREQ_IP4_R2_MIN, self.ip4, self.ip6))
        #   return False
        # if hz6_R2 < const.SIB_FREQ_IP6_R2_MIN_LOWRT:
        #   self.sibling_status = const.SIB_STATUS_IP6_R2_TOO_LOW
        #   log.error('IPv6 - r-squared below defined threshold (< {0}) - maybe randomized TS: {1} / {2}'.format(const.SIB_FREQ_IP6_R2_MIN, self.ip4, self.ip6))
        #   return False

        self.hz4, self.Xi4, self.Vi4, self.hz4_R2, self.hz4_raw = hz4, Xi4, Vi4, hz4_R2, hz4_raw
        self.hz6, self.Xi6, self.Vi6, self.hz6_R2, self.hz6_raw = hz6, Xi6, Vi6, hz6_R2, hz6_raw
        self.hz_diff = abs(hz4_raw - hz6_raw)
        self.hz_rsqrdiff = abs(self.hz4_R2 - self.hz6_R2)

        return True

    def _calc_outlier_removal(self, ipversion):
        # TODO: how is this different from super's impl?
        # remove outliers off the confidence level
        if ipversion == 4:
            offsets = self.tcp_ts_offsets4
        elif ipversion == 6:
            offsets = self.tcp_ts_offsets6

        y_vals = [y for x, y in offsets]

        with numpy.errstate(invalid='raise'):
            try:
                mean = numpy.mean(y_vals)
                stddev = numpy.std(y_vals)  # may raise numpy warning for malformed array
            except Exception as e:
                log.error(
                    '[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))

        lower, upper = (
            mean - const.SIB_Z_SCORE_CONFIDENCE_LEVEL_97 * stddev,
            mean + const.SIB_Z_SCORE_CONFIDENCE_LEVEL_97 * stddev)
        cleaned_arr = []

        for value_pair in offsets:  # list of tuples
            if value_pair[1] < lower or value_pair[1] > upper:
                continue
            cleaned_arr.append(value_pair)

        return cleaned_arr

    def _calc_dynamic_range(self, ipversion=None):
        # TODO: how is this different from super's impl?
        # we do not prune the array in low runtime setting
        if ipversion == 4:
            offset_arr = self.cleaned_mean4_sigma
        elif ipversion == 6:
            offset_arr = self.cleaned_mean6_sigma
        else:
            log.error('Invalid ipversion provided')
            return None

        try:
            offsets = sorted([y for _, y in offset_arr])
            length = len(offsets)
            # lower_index = int(round((const.SIB_DYNRNG_LOWER_CUT_PERCENT * length) / 100))
            # upper_index = int(round((const.SIB_DYNRNG_UPPER_CUT_PERCENT * length) / 100))

            low_val = offsets[0]  # lower_index
            high_val = offsets[length - 1]  # upper_index - 1
            range = high_val - low_val
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return None

        return range

    #### SPLINE calculations
    ##############################################################################
    def _calc_equal_bin_size(self, offsets, nr_bins):
        # TODO: how is this different from super's impl?
        start = offsets[0][0]  # list(tuple(x, y))
        stop = offsets[-1][0]
        return round((stop - start) / nr_bins, 1)

    def _calc_spline(self, bin_size, packed_arr):
        # TODO: how is this different from super's impl?
        try:
            x, y = zip(*packed_arr)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return None

        spline_spacing = self.number_of_timestamps  # int(self.number_of_timestamps / bin_size)
        xs = numpy.arange(x[0], x[-1], spline_spacing)

        nr_bins = int(self.number_of_timestamps / 2)  # safety first
        knots = [x[0] + i * bin_size for i in range(1, nr_bins)]

        try:
            # according to scipy docs removing first and last knot
            # https://docs.scipy.org/doc/scipy/reference/generated/scipy.interpolate.LSQUnivariateSpline.html
            # knots = interpolate.UnivariateSpline(x, y).get_knots()
            spl = interpolate.LSQUnivariateSpline(x, y, knots[1:-1], w=None, bbox=[None, None],
                                                  k=const.SIB_SPLINE_DEGREE)
            curve = spl(xs)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return None

        return (curve, xs)

    def calc_spline(self):
        # TODO: how is this different from super's impl?
        nr_bins = self.number_of_timestamps - 2
        try:
            bin_size4 = self._calc_equal_bin_size(self.cleaned_mean4_sigma, nr_bins)
            bin_size6 = self._calc_equal_bin_size(self.cleaned_mean6_sigma, nr_bins)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        if not bin_size4 or not bin_size6:
            return False

        self.bin_size4, self.bin_size6 = bin_size4, bin_size6

        # eliminate first and last points for spline computation
        packed4 = self.cleaned_mean4_sigma[1: -1]
        packed6 = self.cleaned_mean6_sigma[1: -1]

        res4 = self._calc_spline(self.bin_size4, packed4)
        res6 = self._calc_spline(self.bin_size6, packed6)

        if not res4 or not res6:
            return False

        self.spline_arr4, self.xs4 = res4
        self.spline_arr6, self.xs6 = res6
        return True

    ##############################################################################

    def evaluate(self):
        # TODO: how is this different from super's impl?
        if self.calc_finished:
            log.warning(
                'Already evaluated SiblingCandidate (result: {0}) {1} / {2} -> {3}'.format(self.is_sibling, self.ip4,
                                                                                           self.ip6,
                                                                                           self.sibling_status))
            return self.is_sibling

        # check ssh keys
        # self.ssh_keys_match = self.keys_match() - replaced by new api
        # self.ssh_agents_match = self.agents_match() - replaced by new api

        try:

            if not self.calc_frequency():
                raise SiblingEvaluationError()

            if not self.calc_raw_tcp_timestamp_value():
                log.error('Raw TCP timestamp difference calculation error')
                raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_RAW_TS_DISTANCE_ERROR)

            # DO NOT DECIDE HERE => ML should do this!
            # check v4/v6 frequencies and r-squared match
            # if self.hz_diff > const.SIB_FREQ_HZ_DIFF_MAX_LOWRT or self.hz_rsqrdiff > const.SIB_FREQ_R2_DIFF_MAX_LOWRT:
            #   log.error('Frequency difference too high')
            #   raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_FREQ_DIFF_TOO_HIGH)

            if const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES and self.number_of_timestamps >= const.SIB_LOWRT_CALC_ADDITIONAL_FEATURES_MIN_TIMESTAMPS:
                # Calculations work for two timestamps including dynamic range
                if not self.calc_time_offsets():
                    log.error('Time offsets calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_ALL_OFFSET_ARRAY_ERROR)

                if not self.calc_outlier_removal():
                    log.error('Outlier calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_MEAN_REMOVAL_ERROR)

                if not self.calc_pairwise_point_distance():
                    log.error('Pairwise point distance calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_PPD_ERROR)

                if not self.calc_ppd_mean_median_thresholds():
                    log.error('PPD mean/median threshold calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_PPD_THRESHOLD_ERROR)

                if not self.calc_sigma_outlier_removal():
                    log.error('Two sigma outlier removal calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_SIGMA_OUTLIER_REMOVAL_ERROR)

                if not self.calc_dynamic_range():
                    log.error('Dynamic range calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_DYNAMIC_RANGE_ERROR)

                if not self.calc_alpha():  # skew angle
                    log.error('Angle alpha calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_ALPHA_ERROR)

                if not self.calc_theta():  # Beverly Section 3.3; the angle between the lines built by drawing alpha4/alpha6
                    log.error(
                        'Theta calculation error')  # if theta < tau (threshold value = 1.0) then inferred to be siblings
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_THETA_ERROR)

                ##########################################################################

            if const.SIB_LOWRT_CALC_SPLINE and self.number_of_timestamps >= const.SIB_LOWRT_MIN_TIMESTAMPS_FULL_CALC:
                # We limit the number of timestamps to at least x to get useful results for spline calculations
                if not self.calc_spline():
                    log.error('Spline calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_SPLINE_CALC_ERROR)

                if not self.calc_curve_mapping():
                    log.error('Curve mapping calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_CURVE_MAPPING_ERROR)

                if not self.calc_curve_diff_percent():
                    log.error('Curve percentage mapping calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_CURVE_PERCENT_MAPPING_ERROR)

            self.calc_finished = True

        except SiblingEvaluationError as e:
            self.calc_finished = True
            self.calc_error = True
            if e.sibling_status is not None:
                self.sibling_status = e.sibling_status
        finally:
            # always check if we can determine sibling status based on raw ts val diff
            raw_ts_diff = getattr(self, 'raw_timestamp_diff', None)

            # TODO: ask ml model or other algorithms for sibling decision

            if raw_ts_diff and raw_ts_diff <= LowRTSiblingCandidate.TS_DIFF_THRESHOLD:  # sibling based on raw ts val diff
                if self.calc_error:  # if calc_error occurred we append the status message
                    self.sibling_status = '{0},{1}'.format(self.sibling_status,
                                                           const.SIB_STATUS_IS_SIBLING_RAW_TS_VAL_DIFF)
                else:
                    self.sibling_status = const.SIB_STATUS_IS_SIBLING_RAW_TS_VAL_DIFF
                self.is_sibling = True
                return True
            else:
                # no sibling
                if self.calc_error:  # if calc_error occurred we append the status message
                    self.sibling_status = '{0},{1}'.format(self.sibling_status, const.SIB_STATUS_IS_NO_SIBLING)
                else:
                    self.sibling_status = const.SIB_STATUS_IS_NO_SIBLING
                self.is_sibling = False
                return False
