# libsiblings/siblingcandidate.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

import collections

import matplotlib.pyplot as plt
import numpy
from scipy import interpolate, stats

from .exception import SiblingEvaluationError
from .target import Target
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
        self.sibling_status = const.SIB_STATUS_UNKNOWN
        self.calc_finished = False  # flag to check if calculations have finished (due to error or valid result)
        self.is_sibling = False
        self.calc_error = False  # flag to check if exception occurred -> correct status assignment

        self.ip4, self.port4 = target4.address, target4.port
        self.ip6, self.port6 = target6.address, target6.port
        self.ip4_tcpopts, self.ip6_tcpopts = target4.tcp_options, target6.tcp_options
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
        # if None, no geo information available; additionally, fills self.geodiffs if locations differ and available
        self.geoloc_diff = self.calc_geolocation_differ()

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

    def plot(
            self, fname=None, func=None, funckwargs=None, title=None, titlefontsize=10, xticks=None, xlabel=None,
            ylabel=None, legend=None
    ):
        """
        Plot data to a matplotlib.pyplot figure.

        If domains are available, use the alphabetically first domain as plot title
        (as long as the title argument is omitted)

        fname           file name to write the figure to (use extension as format indicator)
        func            function which should be called with the figure (signature: [plt.Figure, **funckwargs])
        funckwargs      dict of kwargs intended to use with 'func' and unrolled with '**'
        title           plot title
        titlefontsize   font size to use for title
        xticks          array containing ticks for the x axis
        xlabel          array with x axis labels
        ylabel          array with y axis labels
        legend          dict containing kwargs used with plt.legend()
                            (https://matplotlib.org/api/_as_gen/matplotlib.pyplot.legend.html)
        """
        if not self.calc_finished:
            log.warning('Calculations not finished for {0} / {1} - Nothing to plot ...'.format(self.ip4, self.ip6))
            return False

        if not (
                hasattr(self, 'cleaned_mean4')
                and hasattr(self, 'cleaned_mean6')
                and hasattr(self, 'spline_arr4')
                and hasattr(self, 'spline_arr6')
        ):
            log.warning('No data to plot ... Ignoring {0} / {1}'.format(self.ip4, self.ip6))
            return False

        fig = plt.figure()
        axis1 = fig.add_subplot(111)  # nrows, ncols, plot_number
        x4, y4 = zip(*self.cleaned_mean4)
        x6, y6 = zip(*self.cleaned_mean6)

        # 'bo' -> blue circles -> fmt parameter https://matplotlib.org/api/_as_gen/matplotlib.pyplot.plot.html
        axis1.plot(x4, y4, 'bo', color='blue', alpha=0.4, label='IPv4')
        axis1.plot(x6, y6, 'bo', color='red', alpha=0.4, label='IPv6')

        axis1.plot(self.xs4, self.spline_arr4, linewidth=4, color='blue', alpha=0.4)
        axis1.plot(self.xs6, self.spline_arr6, linewidth=4, color='red', alpha=0.4)

        if legend:
            plt.legend(**legend)
        else:
            plt.legend(loc='lower right')

        if title:
            plt.title(title, fontsize=titlefontsize)
        else:
            if self.domains:
                domain = sorted(list(self.domains))[0]
                titlestr = '{0}\n{1} / {2}'.format(domain, self.ip4, self.ip6)
            else:
                titlestr = '{0} / {1}'.format(self.ip4, self.ip6)
            plt.title(titlestr, fontsize=titlefontsize)

        if xlabel:
            plt.xlabel(xlabel)
        else:
            plt.xlabel('measurement time (h)')

        if ylabel:
            plt.ylabel(ylabel)
        else:
            plt.ylabel('observed offset (msec)')

        if xticks:
            axis1.set_xticklabels(xticks)
        else:
            ticks = axis1.get_xticks() / 3600  # set xticks on an hourly basis
            ticks = [round(t, 1) for t in ticks]
            axis1.set_xticklabels(ticks)

        if func:
            func(fig, **funckwargs)
        if fname:
            plt.savefig(fname)

        plt.close(fig)

        return True

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

    def get_results(self):
        """
        Return nearly all results of the calculations.
        """
        results = {}
        try:
            results['ip4'] = self.ip4
            results['ip6'] = self.ip6
            results['port4'] = self.port4
            results['port6'] = self.port6
            results['domains'] = getattr(self, 'domains', None)
            results['hz4'] = getattr(self, 'hz4', None)
            results['hz6'] = getattr(self, 'hz6', None)
            results['hz_diff'] = getattr(self, 'hz_diff', None)
            results['hz4_R2'] = getattr(self, 'hz4_R2', None)
            results['hz6_R2'] = getattr(self, 'hz6_R2', None)
            results['hz_rsqrdiff'] = getattr(self, 'hz_rsqrdiff', None)
            results['raw_ts_diff'] = getattr(self, 'raw_timestamp_diff', None)
            results['alpha4'] = getattr(self, 'alpha4', None)
            results['alpha6'] = getattr(self, 'alpha6', None)
            results['alphadiff'] = getattr(self, 'alphadiff', None)
            results['rsqr4'] = getattr(self, 'rsqr4', None)
            results['rsqr6'] = getattr(self, 'rsqr6', None)
            results['rsqrdiff'] = getattr(self, 'rsqrdiff', None)
            results['theta'] = getattr(self, 'theta', None)
            results['dynrange4'] = getattr(self, 'dynrange4', None)
            results['dynrange6'] = getattr(self, 'dynrange6', None)
            results['dynrange_avg'] = getattr(self, 'dynrange_avg', None)
            results['dynrange_diff'] = getattr(self, 'dynrange_diff', None)
            results['dynrange_diff_rel'] = getattr(self, 'dynrange_diff_rel', None)
            results['spl_mean4'] = getattr(self, 'spl_mean4', None)
            results['spl_mean6'] = getattr(self, 'spl_mean6', None)
            results['spl_diff'] = getattr(self, 'spl_diff', None)
            results['spl_diff_scaled'] = getattr(self, 'spl_diff_scaled', None)
            results['spl_percent_val'] = getattr(self, 'spl_percent_val', None)  # perc_85_val
            results['ip4_tcpopts'] = getattr(self, 'ip4_tcpopts', None)
            results['ip6_tcpopts'] = getattr(self, 'ip6_tcpopts', None)
            results['status'] = getattr(self, 'sibling_status', None)
            results['is_sibling'] = getattr(self, 'is_sibling', None)
            results['geo4'] = getattr(self, 'geo4', None)
            results['geo6'] = getattr(self, 'geo6', None)
            results['geoloc_diff'] = getattr(self, 'geoloc_diff', None)
            results['ssh_keys_match'] = getattr(self, 'ssh_keys_match', None)
            results['ssh_agents_match'] = getattr(self, 'ssh_agents_match', None)
        except Exception as e:
            log.error('Exception: {0} - {1}'.format(type(e).__name__, e))
            return None

        return results

    def evaluate(self) -> bool:
        """
        Invoke sibling evaluation and return whether the result as boolean.

        This changes behaviour depending on some settings from libconstants.

        The result is cached in the instance. Any error that occurs is stored in the self.calc_error.
        """
        if self.calc_finished:
            log.warning('Already evaluated SiblingCandidate (result: {0}) {1} / {2} -> {3}'.format(
                self.is_sibling, self.ip4, self.ip6, self.sibling_status
            ))
            return self.is_sibling

        # check ssh keys
        self.ssh_keys_match = self.keys_match()
        self.ssh_agents_match = self.agents_match()

        # start sibling calculations
        # set sibling_status each step by calling calculations and stop on error
        try:

            # TCP options check
            # if self.tcp_opts_differ is None:
            #   log.warning('Ignoring TCP options (not available) for {0} / {1}'.format(self.ip4, self.ip6))
            # elif self.tcp_opts_differ == True:
            #   raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_TCP_OPTIONS_DIFFER)

            # frequency calculation
            if not self.calc_frequency():
                # set status and hz4, Xi4, Vi4, hz4_R2, hz4_raw; hz6, Xi6, Vi6, hz6_R2, hz6_raw
                raise SiblingEvaluationError()

            # calculate and check raw tcp timestamp value
            if not self.calc_raw_tcp_timestamp_value():
                # sets raw_timestamp_diff
                log.error('Raw TCP timestamp difference calculation error')
                raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_RAW_TS_DISTANCE_ERROR)

            # DO NOT DECIDE HERE => ML should do this!
            # # check v4/v6 frequencies and r-squared match
            # if self.hz_diff > const.SIB_FREQ_HZ_DIFF_MAX or self.hz_rsqrdiff > const.SIB_FREQ_R2_DIFF_MAX:
            #   log.error('Frequency difference too high')
            #   raise SiblingEvaluationError(sibling_status = const.SIB_STATUS_FREQ_DIFF_TOO_HIGH)

            if const.SIB_FRT_CALC_ADDITIONAL_FEATURES:

                # offset calculations
                if not self.calc_time_offsets():
                    # set status and tcp_ts_offsets4, tcp_ts_offsets6
                    raise SiblingEvaluationError()

                # denoise calculations
                if not self.calc_denoise():
                    # set status and denoised4 and denoised6
                    raise SiblingEvaluationError()

                # calculate outlier removal
                if not self.calc_outlier_removal():
                    log.error('Mean removal error')
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

                if not self.calc_theta():
                    # Beverly Section 3.3; the angle between the lines built by drawing alpha4/alpha6
                    # if theta < tau (threshold value = 1.0) then inferred to be siblings
                    log.error('Theta calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_THETA_ERROR)

            if const.SIB_FRT_CALC_SPLINE:
                if not self.calc_spline():
                    log.error('Spline calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_SPLINE_CALC_ERROR)

                if not self.calc_curve_mapping():
                    log.error('Curve mapping calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_CURVE_MAPPING_ERROR)

                if not self.calc_curve_diff_percent():
                    log.error('Curve percentage mapping calculation error')
                    raise SiblingEvaluationError(sibling_status=const.SIB_STATUS_CURVE_PERCENT_MAPPING_ERROR)
        except SiblingEvaluationError as e:
            self.calc_error = True
            if e.sibling_status is not None:
                self.sibling_status = e.sibling_status
        finally:
            self.calc_finished = True

            # always check if we can determine sibling status based on raw ts val diff
            raw_ts_diff = getattr(self, 'raw_timestamp_diff', None)

            # TODO: ask ml model or other algorithms for sibling decision

            if raw_ts_diff and raw_ts_diff <= SiblingCandidate.TS_DIFF_THRESHOLD:  # sibling based on raw ts val diff
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

    def calc_geolocation_differ(self, geoloc_obj=None):
        # TODO: MaxMind API changed, if we need this again, check here:
        # https://blog.maxmind.com/2019/12/18/significant-changes-to-accessing-and-using-geolite2-databases/
        geo = None
        if geoloc_obj:
            geo = geoloc_obj
        if not geo:
            return None

        match, diffs, data4, data6 = geo.match(self.ip4, self.ip6, get_diffs=True)
        if match is None:  # explicitly test for None if information was not available
            self.geodiffs = None
            return None

        # country_iso_code-continent_code
        self.geo4 = '-'.join([str(v) if v is not None else '?' for v in data4.values()])
        self.geo6 = '-'.join([str(v) if v is not None else '?' for v in data6.values()])

        if not match:
            s = []
            for k, v in diffs.items():
                s.append('{0} <-> {1}'.format(v[0], v[1]))
            log.debug('Geolocation differs - {0} / {1} - {2}'.format(self.ip4, self.ip6, ', '.join(s)))
            self.geodiffs = diffs
            return match
        else:
            self.geodiffs = None
            return match

    def _calc_frequency(self, ipversion=None):
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
        else:
            return (None, None, None, None, None)

        nr_timestamps = len(recv_ts)  # already identical length

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

        # We do not check monotonicity -> check rval**2 instead -> if low -> probably randomized timestamps
        ############################################################################
        # https://stackoverflow.com/a/10996196
        # diff = numpy.diff(Vi_arr)
        # indices = []
        # for i, val in enumerate(diff):
        #   if val < 1:
        #     indices.append(i)
        #
        # if len(indices) >= int(len(Vi_arr) * const.SIB_TS_MONOTONICITY_PERCENTAGE):
        #   log.error('IPv{0} error: more than {1}% of timestamps to be removed for strict monotonicity!'.format(ipversion, int(const.SIB_TS_MONOTONICITY_PERCENTAGE * 100)))
        #   return (None, None, None, None, None)
        #
        # Xi_arr = numpy.delete(Xi_arr, indices)
        # Vi_arr = numpy.delete(Vi_arr, indices)

        # numpy.all(numpy.diff(Vi_arr) >= 0) # probably more elegant way but returns new array with diffs (slicing only uses array views (twice as fast!))
        # if not numpy.all(Vi_arr[1:] >= Vi_arr[:-1]): # non-monotonic after adjustment -> probably randomized timestamps
        #   return (None, None, None, None, None)
        ############################################################################
        ############################################################################

        # perform regression
        slope_raw, intercept, rval, pval, stderr = stats.linregress(Xi_arr, Vi_arr)
        hz_R2 = rval * rval  # https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.linregress.html
        hz = round(slope_raw)  # Kohno et al. Section 4.3

        return (hz, Xi_arr, Vi_arr, hz_R2, slope_raw)

    def calc_frequency(self):
        hz4, Xi4, Vi4, hz4_R2, hz4_raw = self._calc_frequency(ipversion=4)
        hz6, Xi6, Vi6, hz6_R2, hz6_raw = self._calc_frequency(ipversion=6)

        # not necessary anymore -> randomization can be checked by inspecting rval**2
        # if not hz4 and not hz6:
        #   self.sibling_status = const.SIB_STATUS_ALL_RANDOMIZED_TS
        #   log.error('Both IPs probably randomized timestamps: {0} / {1}'.format(self.ip4, self.ip6))
        #   return False
        #
        # if not hz4:
        #   self.sibling_status = const.SIB_STATUS_IP4_RANDOMIZED_TS
        #   log.error('IPv4 - Probably randomized timestamps: {0} / {1}'.format(self.ip4, self.ip6))
        #   return False
        #
        # if not hz6:
        #   self.sibling_status = const.SIB_STATUS_IP6_RANDOMIZED_TS
        #   log.error('IPv6 - Probably randomized timestamps: {0} / {1}'.format(self.ip4, self.ip6))
        #   return False

        # DO NOT DECIDE HERE => just plain calculations
        # if abs(hz4_raw) < const.SIB_FREQ_IP4_MIN and abs(hz6_raw) < const.SIB_FREQ_IP6_MIN:
        #   self.sibling_status = const.SIB_STATUS_ALL_FREQ_TOO_LOW
        #   log.error('Both IPs frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
        #   return False
        #
        # if abs(hz4_raw) < const.SIB_FREQ_IP4_MIN:
        #   self.sibling_status = const.SIB_STATUS_IP4_FREQ_TOO_LOW
        #   log.error('IPv4 - frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
        #   return False
        #
        # if abs(hz6_raw) < const.SIB_FREQ_IP6_MIN:
        #   self.sibling_status = const.SIB_STATUS_IP6_FREQ_TOO_LOW
        #   log.error('IPv6 - frequency too low ({0} / {1}): {2} / {3}'.format(hz4, hz6, self.ip4, self.ip6))
        #   return False
        #
        # if hz4_R2 < const.SIB_FREQ_IP4_R2_MIN and hz6_R2 < const.SIB_FREQ_IP6_R2_MIN:
        #   self.sibling_status = const.SIB_STATUS_ALL_R2_TOO_LOW
        #   log.error('Both IPs r-squared below defined threshold - maybe randomized TS ({0} / {1}): {2} / {3}'.format(hz4_R2, hz6_R2, self.ip4, self.ip6))
        #   return False
        #
        # if hz4_R2 < const.SIB_FREQ_IP4_R2_MIN:
        #   self.sibling_status = const.SIB_STATUS_IP4_R2_TOO_LOW
        #   log.error('IPv4 - r-squared below defined threshold (< {0}) - maybe randomized TS: {1} / {2}'.format(const.SIB_FREQ_IP4_R2_MIN, self.ip4, self.ip6))
        #   return False
        #
        # if hz6_R2 < const.SIB_FREQ_IP6_R2_MIN:
        #   self.sibling_status = const.SIB_STATUS_IP6_R2_TOO_LOW
        #   log.error('IPv6 - r-squared below defined threshold (< {0}) - maybe randomized TS: {1} / {2}'.format(const.SIB_FREQ_IP6_R2_MIN, self.ip4, self.ip6))
        #   return False

        self.hz4, self.Xi4, self.Vi4, self.hz4_R2, self.hz4_raw = hz4, Xi4, Vi4, hz4_R2, hz4_raw
        self.hz6, self.Xi6, self.Vi6, self.hz6_R2, self.hz6_raw = hz6, Xi6, Vi6, hz6_R2, hz6_raw
        self.hz_diff = abs(self.hz4_raw - self.hz6_raw)
        self.hz_rsqrdiff = abs(self.hz4_R2 - self.hz6_R2)
        return True

    def calc_raw_tcp_timestamp_value(self):
        try:
            # tcp time distance in seconds
            tcp_time_distance = (self.tcp_offset6 - self.tcp_offset4) / numpy.mean(
                [self.hz4_raw, self.hz6_raw])  # both are numpy.int64
            recv_time_distance = self.recv_offset6 - self.recv_offset4  # both are numpy.float64
            raw_timestamp_diff = abs(tcp_time_distance - recv_time_distance)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        self.raw_timestamp_diff = raw_timestamp_diff
        return True

    def _calc_time_offsets(self, ipversion=None):
        if ipversion == 4:
            Xi = self.Xi4
            Vi = self.Vi4
            hz = self.hz4
        elif ipversion == 6:
            Xi = self.Xi6
            Vi = self.Vi6
            hz = self.hz6
        else:
            return None

        offsets = None

        Wi = [round(float(vi) / hz, 6) for vi in Vi]  # seconds with microseconds precision
        Yi = [(wi - xi) * 1000 for wi, xi in zip(Wi, Xi)]  # offset in milliseconds
        offsets = numpy.array([(round(x, 6), round(y, 6)) for x, y in zip(Xi, Yi)])

        return offsets

    def calc_time_offsets(self):
        offset_arr4 = self._calc_time_offsets(ipversion=4)
        offset_arr6 = self._calc_time_offsets(ipversion=6)

        if offset_arr4 is None and offset_arr6 is None:
            self.sibling_status = const.SIB_STATUS_ALL_OFFSET_ARRAY_ERROR
            log.error('Both IPs error during offset array construction: {0} / {1}'.format(self.ip4, self.ip6))
            return False

        if offset_arr4 is None:
            self.sibling_status = const.SIB_STATUS_IP4_OFFSET_ARRAY_ERROR
            log.error('IPv4 - error during offset array construction: {0} / {1}'.format(self.ip4, self.ip6))
            return False

        if offset_arr6 is None:
            self.sibling_status = const.SIB_STATUS_IP6_OFFSET_ARRAY_ERROR
            log.error('IPv6 - error during offset array construction: {0} / {1}'.format(self.ip4, self.ip6))
            return False

        self.tcp_ts_offsets4, self.tcp_ts_offsets6 = offset_arr4, offset_arr6
        return True

    def _calc_denoise(self, ipversion=None):
        # Divide all probes at hourly intervals to a list.
        # Take the minimum of the hourly tcp offset value (y val)
        # add the corresponding received time (x val) to min_arr.
        if ipversion == 4:
            offsets = self.tcp_ts_offsets4
        elif ipversion == 6:
            offsets = self.tcp_ts_offsets6
        else:
            return None

        recv_times, tcp_offsets = zip(*offsets)  # zip applied to numpy array returns tuples
        recv_times_length = len(recv_times)

        start = 0
        end = 120
        const_multiplier = 120
        n = 1
        # hold_x = 0 # really necessary?
        # hold_y = 0 # really necessary?

        recv_times_per_h = []  # hold all receive times within the current hour
        tcp_offsets_per_h = []  # hold all offsets within the current hour
        all_recv_times = []  # holds all hour based lists
        all_tcp_offsets = []  # holds all hour based lists

        for ctr, current_recv_time in enumerate(recv_times, 1):
            if start <= current_recv_time < end:
                recv_times_per_h.append(current_recv_time)
                tcp_offsets_per_h.append(tcp_offsets[ctr - 1])
            else:
                # hold_x = current_recv_time
                # hold_y = tcp_offsets[ctr - 1]

                all_recv_times.append(recv_times_per_h)
                all_tcp_offsets.append(tcp_offsets_per_h)
                recv_times_per_h = []
                tcp_offsets_per_h = []
                recv_times_per_h.append(current_recv_time)  # hold_x
                tcp_offsets_per_h.append(tcp_offsets[ctr - 1])  # hold_y

                start = end
                n = n + 1
                end = n * const_multiplier

            if ctr == recv_times_length and tcp_offsets_per_h:  # do not forget to add the last hour list (if not empty)
                all_recv_times.append(recv_times_per_h)
                all_tcp_offsets.append(tcp_offsets_per_h)

        min_arr = []  # collect min values from hour based lists

        for i in range(len(all_tcp_offsets)):
            try:  # get the index of the min value within the current hour
                index = numpy.array(all_tcp_offsets[i]).argmin()
            except ValueError as e:
                log.error('[{ip4} / {ip6}] ValueError at argmin(): {0}'.format(e, ip4=self.ip4, ip6=self.ip6))
                return None

            min_per_probe = all_tcp_offsets[i][index]
            corresponding_x_per_probe = all_recv_times[i][index]
            min_arr.append((corresponding_x_per_probe, min_per_probe))

        return min_arr

    def calc_denoise(self):
        denoised4 = self._calc_denoise(ipversion=4)
        denoised6 = self._calc_denoise(ipversion=6)

        if denoised4 is None and denoised6 is None:
            self.sibling_status = const.SIB_STATUS_ALL_DENOISED_ARRAY_ERROR
            log.error('Both IPs error during denoised array construction: {0} / {1}'.format(self.ip4, self.ip6))
            return False

        if denoised4 is None:
            self.sibling_status = const.SIB_STATUS_IP4_DENOISED_ARRAY_ERROR
            log.error('IPv4 - error during denoised array construction: {0} / {1}'.format(self.ip4, self.ip6))
            return False

        if denoised6 is None:
            self.sibling_status = const.SIB_STATUS_IP6_DENOISED_ARRAY_ERROR
            log.error('IPv6 - error during denoised array construction: {0} / {1}'.format(self.ip4, self.ip6))
            return False

        self.denoised4 = denoised4
        self.denoised6 = denoised6
        return True

    def _calc_outlier_removal(self, ipversion=None):
        # remove outliers off the confidence level
        if ipversion == 4:
            offsets = self.denoised4
        elif ipversion == 6:
            offsets = self.denoised6
        else:
            log.error('Invalid ipversion provided')
            return None

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

    def calc_outlier_removal(self):
        cleaned_mean4 = self._calc_outlier_removal(ipversion=4)
        cleaned_mean6 = self._calc_outlier_removal(ipversion=6)

        if cleaned_mean4 and cleaned_mean6:
            self.cleaned_mean4 = cleaned_mean4
            self.cleaned_mean6 = cleaned_mean6
            return True
        else:
            return False

    def calc_pairwise_point_distance(self):
        # Calculate pairwise point distance between candidate offset values
        x4, y4 = zip(*self.cleaned_mean4)
        x6, y6 = zip(*self.cleaned_mean6)

        max_index = min(len(x4), len(x6))  # if one of the IPs stop responding -> different offset array size

        np_x6 = numpy.array(x6)
        index6_arr = []  # holds the indices of the closest IPv6 arrival times relative to every IPv4 arrival time
        ppd_arr = []

        for index in range(
                max_index):  # find the closest arrival time for IPv6 being sj6 (index) to that of IPv4 si4 (closest arrival time)
            try:
                index6 = numpy.abs(np_x6 - x4[index]).argmin()
            except Exception as e:  # ValueError
                log.error(
                    '[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
                return False

            index6_arr.append(index6)

        for index4 in range(
                max_index):  # get y values for those pair of points and calculate the absolute pairwise distance
            try:
                si4 = y4[index4]
                sj6 = y6[index6_arr[index4]]
                ppd_arr.append(abs(si4 - sj6))
            except Exception as e:
                log.error(
                    '[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
                return False

        global_min = min(min(y4), min(y6))
        global_max = max(max(y4), max(y6))
        range_ymin_ymax = abs(global_min - global_max)  # range between the smallest and biggest value observed

        self.ppd_arr, self.ppd_index6_arr, self.ppd_range_raw = ppd_arr, index6_arr, range_ymin_ymax
        return True

    def calc_ppd_mean_median_thresholds(self):
        mad_lst = []  # median absolute deviation
        try:
            mean = numpy.mean(self.ppd_arr)
            stddev_mean = numpy.std(self.ppd_arr)
            median = numpy.median(self.ppd_arr)

            for point in self.ppd_arr:
                mad_lst.append(abs(point - median))  # median absolute deviation

            # https://en.wikipedia.org/wiki/Median_absolute_deviation#Relation_to_standard_deviation
            stddev_median = const.SIB_CONSISTENCY_CONSTANT_K * numpy.median(mad_lst)

            median_threshhold = (median - const.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stddev_median,
                                 median + const.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stddev_median)
            mean_threshhold = (mean - const.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stddev_mean,
                               mean + const.SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 * stddev_mean)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        self.ppd_mean_threshold, self.ppd_median_threshold = mean_threshhold, median_threshhold
        return True

    def calc_sigma_outlier_removal(self):
        clean4 = []
        clean6 = []
        arr6 = []
        ppd_arr_pruned = []

        try:
            lower, upper = self.ppd_median_threshold

            for index6 in self.ppd_index6_arr:
                arr6.append(self.cleaned_mean6[index6])

            for i in range(len(self.ppd_arr)):
                if not self.ppd_arr[i] < lower and not self.ppd_arr[i] > upper:
                    clean4.append(self.cleaned_mean4[i])
                    clean6.append(arr6[i])
                    ppd_arr_pruned.append(self.ppd_arr[i])

            self.ppd_range_pruned = max(ppd_arr_pruned) - min(ppd_arr_pruned)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        self.cleaned_mean4_sigma, self.cleaned_mean6_sigma = clean4, clean6
        self.ppd_arr_pruned = ppd_arr_pruned
        return True

    def _calc_alpha(self, ipversion=None):
        if ipversion == 4:
            offset_arr = self.cleaned_mean4_sigma
        elif ipversion == 6:
            offset_arr = self.cleaned_mean6_sigma
        else:
            log.error('Invalid ipversion provided')
            return None

        x_arr, y_arr = zip(*offset_arr)

        try:
            slope_raw, intercept, rval, pval, stderr = stats.linregress(x_arr, y_arr)
            medslope, medintercept, lo_slope, up_slope = stats.mstats.theilslopes(y_arr, x_arr)
        # except FloatingPointError as e:
        #   log.error('[{ip4} / {ip6}] Exception: {0}'.format(e, ip4 = self.ip4, ip6 = self.ip6))
        #   return None
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return None

        return (medslope, medintercept, rval, rval ** 2)

    def calc_alpha(self):
        ret4 = self._calc_alpha(ipversion=4)
        ret6 = self._calc_alpha(ipversion=6)

        if not ret4 or not ret6:
            return False

        alpha4, _, _, r4_sqr = ret4
        alpha6, _, _, r6_sqr = ret6

        try:
            alphadiff = abs(alpha4 - alpha6)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        try:
            rsqrdiff = abs(r4_sqr - r6_sqr)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        self.alpha4, self.alpha6, self.alphadiff = alpha4, alpha6, alphadiff
        self.rsqr4, self.rsqr6, self.rsqrdiff = r4_sqr, r6_sqr, rsqrdiff
        return True

    def calc_theta(self):
        try:
            fraction = (self.alpha4 - self.alpha6) / (1 + self.alpha4 * self.alpha6)
            theta = numpy.arctan(abs(fraction))
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        self.theta = theta
        return True

    def _calc_dynamic_range(self, ipversion=None):
        # prune 2.5% form upper and lower array content and calculate range between lowest and highest value
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
            lower_index = int(round((const.SIB_DYNRNG_LOWER_CUT_PERCENT * length) / 100))
            upper_index = int(round((const.SIB_DYNRNG_UPPER_CUT_PERCENT * length) / 100))

            low_val = offsets[lower_index]
            high_val = offsets[upper_index - 1]
            range = high_val - low_val
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return None

        return range

    def calc_dynamic_range(self):
        dynrange4 = self._calc_dynamic_range(ipversion=4)
        dynrange6 = self._calc_dynamic_range(ipversion=6)

        if not dynrange4 or not dynrange6:
            return False

        try:
            dynrange_diff = abs(dynrange4 - dynrange6)
            dynrange_avg = numpy.mean([dynrange4, dynrange6])
            dynrange_diff_rel = dynrange_diff / dynrange_avg
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        self.dynrange4, self.dynrange6 = dynrange4, dynrange6
        self.dynrange_diff, self.dynrange_diff_rel = dynrange_diff, dynrange_diff_rel
        self.dynrange_avg = dynrange_avg
        return True

    #### SPLINE calculations
    ##############################################################################
    def _calc_equal_bin_size(self, offsets, nr_bins):
        start = offsets[0][0]  # list(tuple(x, y))
        stop = offsets[-1][0]
        return round((stop - start) / nr_bins, 1)

    def _calc_spline(self, bin_size, packed_arr):
        try:
            x, y = zip(*packed_arr)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return None

        xs = numpy.arange(x[0], x[-1], const.SIB_SPLINE_XSPLINE_SPACING)

        knots = [x[0] + i * bin_size for i in range(1, const.SIB_SPLINE_NR_BINS)]

        try:
            # according to scipy docs removing first and last knot
            # https://docs.scipy.org/doc/scipy/reference/generated/scipy.interpolate.LSQUnivariateSpline.html
            spl = interpolate.LSQUnivariateSpline(x, y, knots[1:-1], w=None, bbox=[None, None],
                                                  k=const.SIB_SPLINE_DEGREE)
            curve = spl(xs)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return None

        return (curve, xs)

    def calc_spline(self):
        try:
            bin_size4 = self._calc_equal_bin_size(self.cleaned_mean4_sigma, const.SIB_SPLINE_NR_BINS)
            bin_size6 = self._calc_equal_bin_size(self.cleaned_mean6_sigma, const.SIB_SPLINE_NR_BINS)
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        if not bin_size4 or not bin_size6:
            return False

        self.bin_size4, self.bin_size6 = bin_size4, bin_size6
        # eliminate first and last points for spline computation
        packed4 = self.cleaned_mean4_sigma[const.SIB_SPLINE_LOWER_POINTS_INDEX: const.SIB_SPLINE_UPPER_POINTS_INDEX]
        packed6 = self.cleaned_mean6_sigma[const.SIB_SPLINE_LOWER_POINTS_INDEX: const.SIB_SPLINE_UPPER_POINTS_INDEX]

        res4 = self._calc_spline(self.bin_size4, packed4)
        res6 = self._calc_spline(self.bin_size6, packed6)

        if not res4 or not res6:
            return False

        self.spline_arr4, self.xs4 = res4
        self.spline_arr6, self.xs6 = res6
        return True

    def calc_curve_mapping(self):
        # map the upper curve on the lower one
        try:
            spl_mean4 = numpy.mean(self.spline_arr4)
            spl_mean6 = numpy.mean(self.spline_arr6)
            spl_diff = spl_mean4 - spl_mean6
            max_length = min(len(self.xs4), len(self.xs6))
            spl_mapped_diff = []

            if spl_diff > 0:
                y_mapped = self.spline_arr4[:max_length] - spl_diff
            else:
                y_mapped = self.spline_arr6[:max_length] - abs(spl_diff)

            if spl_diff >= 0:  # v4 curve is the upper one
                x_mapped = self.xs4[:max_length]
                for i in range(max_length):
                    spl_mapped_diff.append(abs(y_mapped[i] - self.spline_arr6[i]))
            else:  # v6 curve is the upper one
                x_mapped = self.xs6[:max_length]
                for i in range(max_length):
                    spl_mapped_diff.append(abs(y_mapped[i] - self.spline_arr4[i]))
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        self.spl_mapped_diff = spl_mapped_diff
        self.spl_mean4, self.spl_mean6 = spl_mean4, spl_mean6
        self.spl_diff = abs(spl_diff)
        self.spl_diff_scaled = spl_diff / self.dynrange_diff
        return True

    def calc_curve_diff_percent(self):
        # calc cumulative distribution function array first
        try:
            spl_counter = collections.Counter(self.spl_mapped_diff)
            keys = list(spl_counter.keys())
            counts = list(spl_counter.values())
            total_counts = sum(counts)
            percents = [100 * (c / total_counts) for c in counts]
            appearances = sorted(spl_counter.items())  # -> returns list of tuples

            suml = 0
            cdf_arr = []

            for val, count in appearances:
                suml = suml + count
                cdf_arr.append((val, suml))

            perc_arr = []
            for val, perc in cdf_arr:
                if const.SIB_SPLINE_LOWER_PERCENT_MAPPING <= perc <= const.SIB_SPLINE_UPPER_PERCENT_MAPPING:
                    perc_arr.append(val)

            # use percentil diff as metric
            mid_index = int(round(len(perc_arr) / 2))
            perc_val = perc_arr[mid_index]
        except Exception as e:
            log.error('[{ip4} / {ip6}] Exception: {0} - {1}'.format(type(e).__name__, e, ip4=self.ip4, ip6=self.ip6))
            return False

        self.spl_percent_val = perc_val
        return True
