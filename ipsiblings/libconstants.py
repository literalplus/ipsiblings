# libconstants.py
#
# (c) 2018 Marco Starke
#


"""
Holds project wide constants.
"""
### minimum python version ###
PYTHON_VERSION_MAJOR = 3
PYTHON_VERSION_MINOR = 6

#### SERVICES AND OPTIMIZATION ####
DISABLE_ALL = True
# Configuration object to apply system dependent optimization settings
OPTIMIZE_OS_SETTINGS = not DISABLE_ALL
WRITE_OS_SETTINGS_TO_FILE = True
OS_SETTINGS_FILE_NAME = 'settings.bak'
# disable time sync during measurements -> OS dependent
DISABLE_TIME_SYNC_SERVICE = not DISABLE_ALL
# set the command to be used in the settings module (preferred) or in the following two constants
TIME_SYNC_START_COMMAND = None  # 'timedatectl set-ntp on'
TIME_SYNC_STOP_COMMAND = None  # 'timedatectl set-ntp off'

# apply firewall rules defined in settings.py for respective OS
FIREWALL_APPLY_RULES = not DISABLE_ALL

##########################
#### OPTION CONSTANTS ####
##########################

# base directory only used if no command line directory is given
# NOTE: Actually, a subdirectory with timestamp is created if no directory is given
#       Also, the value of this variable is overwritten with the actual base directory.
BASE_DIRECTORY = '/root/thesis/data'
# silent node direcotry will be combined with the command line base directory
DIRECTORY_SILENT_NODES = 'silent_nodes'

# harvesting options
# waits X seconds before sending processes are started for the first time
START_SNIFF_PROCESS_DELAY = 2

# DEFAULT RUNTIME 10h - 10k batch Alexa
HARVESTING_RUNTIME = 60 * 60 * 10  # seconds
HARVESTING_INTERVAL = 60  # seconds
HARVESTING_RESULTS_TIMEOUT = 20  # seconds - 1/3 * interval
HARVESTING_RESULTS_TIMEOUT_FINAL = 120  # seconds - 2 * interval

# DEFAULT RUNTIME 10h - 50k batch Cisco
# HARVESTING_RUNTIME = 60 * 60 * 10 # seconds
# HARVESTING_INTERVAL = 120 # seconds
# HARVESTING_RESULTS_TIMEOUT = 40 # seconds - 1/3 * interval
# HARVESTING_RESULTS_TIMEOUT_FINAL = 240 # seconds - 2 * interval

# 5 MIN runtime for ~60 TS
# HARVESTING_RUNTIME = 60 * 5 # seconds
# HARVESTING_INTERVAL = 5 # seconds
# HARVESTING_RESULTS_TIMEOUT = 2
# HARVESTING_RESULTS_TIMEOUT_FINAL = 20

# LOW RUNTIME for batch of 10k candidates of Alexa for example
# HARVESTING_RUNTIME = 80
# HARVESTING_INTERVAL = 8
# HARVESTING_RESULTS_TIMEOUT = 2
# HARVESTING_RESULTS_TIMEOUT_FINAL = 8

# LOW RUNTIME for batch of 50k traces of Cisco for example
# 11,5k nodes at most per batch -> 25s runtime for 4 ports * 11,5k => use 30 seconds for each run
# -> way less time necessary due to optimization of responding nodes
# HARVESTING_RUNTIME = 150
# HARVESTING_INTERVAL = 15
# HARVESTING_RESULTS_TIMEOUT = 5
# HARVESTING_RESULTS_TIMEOUT_FINAL = 10

# TESTING VALUES - ONLY MODIFY THESE PARAMETERS IF TESTING
# HARVESTING_RUNTIME = 64                 # testing value -> 10
# HARVESTING_INTERVAL = 8                 # testing value -> 2
# HARVESTING_RESULTS_TIMEOUT = 4          # testing value -> 1
# HARVESTING_RESULTS_TIMEOUT_FINAL = 8    # testing value -> 2

# CandidatePair constants
CANDIDATE_PAIRS_FILE_NAME = 'candidatepairs.csv'
CANDIDATE_PAIRS_DATA_FILE_NAME = 'timestamp_data.txt'
CANDIDATE_PAIRS_TCP_OPTS_FILE_NAME = 'tcp_options.txt'

# plot file name
PLOT_FILE_NAME = 'plot.pdf'

# results file name
RESULT_FILE_NAME = 'results.csv'

# ip_pairs file name
IP_PAIRS_FILE_NAME = 'ip_pairs.csv'

# ssh keyscan constatns
SSH_PORT = 22
SSH_KEYS_FILENAME = 'ssh-keys.txt'
SSH_AGENTS_FILENAME = 'ssh-agents.txt'
SSH_KEYSCAN_COMMAND = 'ssh-keyscan -f -'

# sibling options and constants
# calc everything beyond raw_timestamp_diff
SIB_FRT_CALC_ADDITIONAL_FEATURES = True
# also calc splines
SIB_FRT_CALC_SPLINE = True
# calculate additional features
SIB_LOWRT_CALC_ADDITIONAL_FEATURES = True
SIB_LOWRT_CALC_ADDITIONAL_FEATURES_MIN_TIMESTAMPS = 8  # this works with 2 timestamps!
# calculate the splines if enough timestamps available
SIB_LOWRT_CALC_SPLINE = False
# low runtime -> do full calculations only if at least x timestamps available
SIB_LOWRT_MIN_TIMESTAMPS_FULL_CALC = 16  # 16 may be still not enough
# used to check if overflow of timestamp counter occurred
# ~1000 timestamp ticks -> 1 to 10 seconds (frequencies of 1Hz to 1000Hz according to RFC)
SIB_TS_OVERFLOW_THRESHOLD = 1000
# percentage of how many timestamps are allowed to be removed from the list to ensure strict monotonicity
SIB_TS_MONOTONICITY_PERCENTAGE = 0.5
# round frequencies to next lower base (e.g 107.2432 -> 100 for 10 [x * round(val / x)]
SIB_FREQ_ROUND_BASE = 10
# lower boundary for remote clock frequency
SIB_FREQ_IP4_MIN = 1
SIB_FREQ_IP6_MIN = 1
# upper boundary for differences of r-squared and frequencies
SIB_FREQ_HZ_DIFF_MAX = 0.25
SIB_FREQ_R2_DIFF_MAX = 0.25
SIB_FREQ_HZ_DIFF_MAX_LOWRT = 0.25
SIB_FREQ_R2_DIFF_MAX_LOWRT = 0.25
# lower boundary for fitting the data to the regression line
SIB_FREQ_IP4_R2_MIN = 0.9
SIB_FREQ_IP6_R2_MIN = 0.9
SIB_FREQ_IP4_R2_MIN_LOWRT = 0.8
SIB_FREQ_IP6_R2_MIN_LOWRT = 0.8
# Z score for confidence level used for mean based outlier removal
SIB_Z_SCORE_CONFIDENCE_LEVEL_97 = 2.17009  # 97% confidence level
SIB_Z_SCORE_CONFIDENCE_LEVEL_98_5 = 2.432  # 98.5% confidence level
SIB_Z_SCORE_CONFIDENCE_LEVEL_95 = 1.96  # 95% confidence level
SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 = 2.00466  # 95,5% confidence level
# consistency constant k -> https://en.wikipedia.org/wiki/Median_absolute_deviation
SIB_CONSISTENCY_CONSTANT_K = 1.4826
# dynamic range: remove the lower and upper X percent for stability against latency-caused outliers
SIB_DYNRNG_LOWER_CUT_PERCENT = 2.5
SIB_DYNRNG_UPPER_CUT_PERCENT = 97.5
# spline calculation:
SIB_SPLINE_DEGREE = 3  # degree of the spline to approximate
SIB_SPLINE_NR_BINS = 12  # number of bins to divide the x range to (paper: 12)
SIB_SPLINE_LOWER_POINTS_INDEX = 8  # eliminate first and
SIB_SPLINE_UPPER_POINTS_INDEX = -8  # last points for spline calculation
SIB_SPLINE_XSPLINE_SPACING = 120  # distance between evenly spaced values of given interval
SIB_SPLINE_LOWER_PERCENT_MAPPING = 84  # lower percentage of curve mapping threshold
SIB_SPLINE_UPPER_PERCENT_MAPPING = 86  # upper percentage of curve mapping threshold

# status of the SiblingCandidate object
SIB_STATUS_UNKNOWN = 'unknown'  # initial status
# positive status
SIB_STATUS_IS_SIBLING_RAW_TS_VAL_DIFF = 'sibling (raw ts val diff)'
# general status
SIB_STATUS_IS_SIBLING = 'sibling'  # final status if sibling
SIB_STATUS_IS_NO_SIBLING = 'NO sibling'  # final status if no sibling
# tcp options check
SIB_STATUS_TCP_OPTIONS_DIFFER = 'tcp options differ'
# frequency calculations
SIB_STATUS_IP4_RANDOMIZED_TS = 'ip4 randomized timestamps'
SIB_STATUS_IP6_RANDOMIZED_TS = 'ip6 randomized timestamps'
SIB_STATUS_ALL_RANDOMIZED_TS = 'ip4 & ip6 randomized timestamps'
SIB_STATUS_IP4_FREQ_TOO_LOW = 'ip4 frequency too low'
SIB_STATUS_IP6_FREQ_TOO_LOW = 'ip6 frequency too low'
SIB_STATUS_ALL_FREQ_TOO_LOW = 'ip4 & ip6 frequency too low'
SIB_STATUS_IP4_R2_TOO_LOW = 'ip4 r-squared too low for frequency linreg'
SIB_STATUS_IP6_R2_TOO_LOW = 'ip6 r-squared too low for frequency linreg'
SIB_STATUS_ALL_R2_TOO_LOW = 'ip4 & ip6 r-squared too low for frequency linreg'
# offset calculations
SIB_STATUS_ALL_OFFSET_ARRAY_ERROR = 'ip4 & ip6 error offset calculation'
SIB_STATUS_IP4_OFFSET_ARRAY_ERROR = 'ip4 error offset calculation'
SIB_STATUS_IP6_OFFSET_ARRAY_ERROR = 'ip6 error offset calculation'
# denoise calculations
SIB_STATUS_ALL_DENOISED_ARRAY_ERROR = 'ip4 & ip6 error denoise calculation'
SIB_STATUS_IP4_DENOISED_ARRAY_ERROR = 'ip4 error denoise calculation'
SIB_STATUS_IP6_DENOISED_ARRAY_ERROR = 'ip6 error denoise calculation'
# frequency and r-squared diff
SIB_STATUS_FREQ_DIFF_TOO_HIGH = 'hz diff too high'
# raw timestamp distance (delta_tcpraw)
SIB_STATUS_RAW_TS_DISTANCE_ERROR = 'raw tcp timestamp error'
# 2nd level denoising; mean removal
SIB_STATUS_MEAN_REMOVAL_ERROR = 'mean removal error'
# pairwise point distance calculation
SIB_STATUS_PPD_ERROR = 'pairwise point distance calculation error'
# PPD threshold calculation error
SIB_STATUS_PPD_THRESHOLD_ERROR = 'pairwise point distance threshold calculation error'
# two sigma outlier removal error
SIB_STATUS_SIGMA_OUTLIER_REMOVAL_ERROR = 'two sigma outlier removal error'
# alpha angle calculation error
SIB_STATUS_ALPHA_ERROR = 'alpha calculation error'
# theta angle calculation error
SIB_STATUS_THETA_ERROR = 'theta calculation error'
# dynamic range calculation error
SIB_STATUS_DYNAMIC_RANGE_ERROR = 'dynamic range calculation error'
# spline calculation error
SIB_STATUS_SPLINE_CALC_ERROR = 'spline calculation error'
# error during curve mapping
SIB_STATUS_CURVE_MAPPING_ERROR = 'curve mapping calculation error'
# error while calculating curve mapping percentage
SIB_STATUS_CURVE_PERCENT_MAPPING_ERROR = 'curve mapping percentage calculation error'
################################################################################


# log levels are set by argparse in main.py
# NOTSET (0) - DEBUG (10) - INFO (20) - WARNING (30) - ERROR (40) - CRITICAL (50)
LOG_FORMAT = '%(asctime)s - %(module)s - %(funcName)s - %(levelname)s: %(message)s'
LOG_LVL_SCAPY = 40  # ERROR - disable warnings

########

# number of hops threshold for checking if IPs belong to CDN
CDN_HOP_THRESHOLD = 3
# file name for writing filtered cdn pairs
CDN_FILTERED_FILENAME = 'cdns_filtered.csv'

########

### timestamp constants ###
PACKET_RESEARCH_MESSAGE = 'research_scan'
V4_PORT = 44242
V6_PORT = 64242
STOP_PORT = 4  # unassigned by IANA (https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
V4_SEQ_NR = 410815
V6_SEQ_NR = 610815
TS_INITIAL_VAL = 1337
###

IP_VERSION_4 = 4
IP_VERSION_6 = 6
IP4 = IP_VERSION_4
IP6 = IP_VERSION_6

PORT_MAX = 65535
PORT_COMMON_START = 1024
