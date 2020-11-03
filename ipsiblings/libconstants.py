# libconstants.py
#
# (c) 2018 Marco Starke
#


"""
Holds project wide constants.
"""

# harvesting options
# DEFAULT RUNTIME 10h - 10k batch Alexa
HARVESTING_RUNTIME = 60 * 60 * 10  # seconds
HARVESTING_INTERVAL = 60  # seconds
HARVESTING_RESULTS_TIMEOUT = 20  # seconds - 1/3 * interval
HARVESTING_RESULTS_TIMEOUT_FINAL = 120  # seconds - 2 * interval

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
SIB_Z_SCORE_CONFIDENCE_LEVEL_95_5 = 2.00466  # 95,5% confidence level
# consistency constant k -> https://en.wikipedia.org/wiki/Median_absolute_deviation
SIB_CONSISTENCY_CONSTANT_K = 1.4826

V4_PORT = 44242
V6_PORT = 64242
# unassigned by IANA (https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml)
STOP_PORT = 4
TS_INITIAL_VAL = 1337
