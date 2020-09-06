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
DISABLE_ALL = False
# Configuration object to apply system dependent optimization settings
OPTIMIZE_OS_SETTINGS = True and not DISABLE_ALL
WRITE_OS_SETTINGS_TO_FILE = True
OS_SETTINGS_FILE_NAME = 'settings.bak'
# disable time sync during measurements -> OS dependent
DISABLE_TIME_SYNC_SERVICE = True and not DISABLE_ALL
# set the command to be used in the settings module (preferred) or in the following two constants
TIME_SYNC_START_COMMAND = None  # 'timedatectl set-ntp on'
TIME_SYNC_STOP_COMMAND = None  # 'timedatectl set-ntp off'

# apply firewall rules defined in settings.py for respective OS
FIREWALL_APPLY_RULES = True and not DISABLE_ALL

#### INTERFACE
# MAC address is found by libtools.get_mac(iface) and set in main.py
IFACE_MAC_ADDRESS = None
IFACE_IP4_ADDRESS = None
IFACE_IP6_ADDRESS = None

##########################
#### OPTION CONSTANTS ####
##########################

# trace set options
NR_TRACES_PER_TRACE_SET = 1  # repeats the traceroute process to find X different traces for one target
INACTIVE_RESULTS_PER_TRACE_SET = 1  # for each target continue with next one if X empty results were obtained
MAX_TRIES_FOR_NEW_TRACE = 1  # continue with next target if X traceroutes to find a new trace were not successful

# base directory only used if no command line directory is given
# NOTE: Actually, a subdirectory with timestamp is created if no directory is given
#       Also, the value of this variable is overwritten with the actual base directory.
BASE_DIRECTORY = '/root/thesis/data'
# write the silent trace set to disk
WRITE_INACTIVE_TRACE_SET = False
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

### holds the instance of the Geo class; initialized in main.py
GEO = None

### MaxMind GeoIP2
GEO_DB_BASE_DIR = '/root/thesis/geoip/'
GEO_CITY_DB_FILE = 'GeoLite2-City.mmdb'
GEO_ASN_DB_FILE = 'GeoLite2-ASN.mmdb'

GEO_CITY_DB_URL = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-City.tar.gz'
GEO_ASN_DB_URL = 'http://geolite.maxmind.com/download/geoip/database/GeoLite2-ASN.tar.gz'

########

### Alexa Top List ###
ALEXA_URL = 'https://s3.amazonaws.com/alexa-static/top-1m.csv.zip'
ALEXA_FILE_NAME = 'top-1m.csv'
ALEXA_RESOLVED_FILE_NAME = 'alexa_resolved.csv'
ALEXA_RESOLVED_FILENAME_ERRORCASE = 'alexa_resolved.csv.error'  # in case of error, all previously resolved entries will be written to this file
ALEXA_UNRESOLVABLE_FILE_NAME = 'alexa_unresolvable.csv'
ALEXA_UNRESOLVABLE_FILENAME_ERRORCASE = 'alexa_unresolvable.csv.error'

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

### traceroute
# used in algorithms.traceroute.py
TRACEROUTE_ADD_SOURCE_IP = False
TRACEROUTE_WITHOUT_DESTINATION_IP = True

### traceroute constants ###
TR_UDP_DEFAULT_SRC_PORT = 33457
TR_UDP_DEFAULT_DST_PORT = 33456
TR_UDP_DST_PORT_USING_U = 53

TR_TCP_DEFAULT_SRC_PORT = 16449
TR_TCP_DEFAULT_DST_PORT = 16963
TR_TCP_DST_PORT_USING_T = 80
###


from .libtraceroute.algorithm.all import ALGORITHMS

ALGORITHMS_AVAILABLE = ALGORITHMS.keys()

#### PORT LIST
## will be initialized in main.py when operation mode (-t/-c) has been chosen
PORT_LIST = None

#### PORT LIST SERVER
##
PORT_LIST_SERVER = [
    22,
    25,
    53,
    80,
    443,
]

#### PORT LIST ROUTER
##
PORT_LIST_ROUTER = [
    # 1, # TCP Port Service Multiplexer (TCPMUX). Historic. Both TCP and UDP have been assigned to TCPMUX by IANA, but by design only TCP is specified
    # 5, # Remote job entry
    7,  # Echo Protocol (RFC 862)
    # 9, # Discard Protocol (RFC 863); (UNOFFICIAL) Wake-on-LAN
    # 11, # Active Users (systat service) - exposes active users on a system (RFC 866)
    # 13, # Daytime Protocol (RFC 867)
    # 15, # (UNOFFICIAL) Previously netstat service
    # 17, # Quote of the Day (QOTD, RFC 865)
    # 18, # Message Send Protocol (RFC 1312)
    # 19, # Character Generator Protocol (RFC 864)
    ####
    20,  # FTP data
    21,  # FTP command
    22,  # SSH
    23,  # telnet
    25,  # SMTP
    37,  # Time Protocol
    38,  # Route Access Protocol (RAP)
    52,  # Xerox Network Systems (XNS) Time Protocol
    53,  # DNS
    54,  # Xerox Network Systems (XNS) clearinghouse
    56,  # Xerox Network Systems (XNS) authentication
    58,  # Xerox Network Systems (XNS) Mail
    # 69, # Trivial FTP
    70,  # Gopher
    79,  # Finger
    80,  # HTTP
    81,  # TorPark Onion routing
    82,  # TorPark control
    87,  # Any private terminal link
    # 88, # Kerberos
    90,  # dnsix (DoD Network Security for Information Exchange) Security Attribute Token Map
    107,  # Remote User Telnet Service (RTelnet)
    108,  # IBM Systems Network Architecture (SNA) gateway access server
    # 109, # POP2
    # 110, # POP3
    111,  # Open Network Computing Remote Procedure Call (ONC RPC, sometimes referred to as Sun RPC)
    # 116, # Simple FTP
    117,  # UUCP Mapping Project (path service)
    # 118, # SQL Services
    # 119, # Network News Transport Protocol (NNTP)
    123,  # NTP
    # 135, # Distributed Computing Environment (DCE) endpoint resolution; Microsoft EPMAP (End Point Mapper), also known as DCE/RPC Locator service, used to remotely manage services, eg DHCP server, DNS server and WINS. Also used by DCOM.
    # 137, # NetBIOS Name Service, used for name registration and resolution
    # 138, # NetBIOS Datagram Service
    # 139, # NetBIOS Session Service
    # 143, # Internet Message Access Protocol (IMAP)
    153,
    # Simple Gateway Monitoring Protocol (SGMP), remote inspection and alteration of gateway management information
    # 156, # Structured Query Language (SQL) Service
    161,  # Simple Network Management Protocol (SNMP)
    162,  # Simple Network Management Protocol Trap (SNMPTRAP)
    # 170, # Print server
    ####
    179,  # Border Gateway Protocol (BGP), exchange routing and reachability information among AS on the Internet
    ####
    # 194, # IRC
    199,  # SNMP multiplexing protocol (SMUX)
    201,  # AppleTalk Routing Maintenance
    # 209, # Quick Mail Transfer Protocol
    213,  # Internetwork Packet Exchange (IPX)
    # 218, # Message posting protocol (MPP)
    # 220, # IMAP v3
    264,  # Border Gateway Multicast Protocol (BGMP)
    # 280, # http-mgmt (?)
    # 300, # Novastor Online Backup / ThinLinc Web Access
    # 311, # Mac OS X Server Admin(officially AppleShare IP Web administration)
    318,  # PKIX Time Stamp Protocol (TSP)
    # 319, # (UDP) Precision Time Protocol (PTP) event messages
    # 320, # (UDP) Precision Time Protocol (PTP) general messages
    # 350, # Mapping of Airline Traffic over Internet Protocol (MATIP) type A
    # 351, # MATIP type B
    # 356, # cloanto-net-1 (used by Cloanto Amiga Explorer and VMs)
    # 366, # On-Demand Mail Relay (ODMR)
    # 369, # Rpc2portmap
    # 370, # codaauth2, Coda authentication server; (UDP) securecast1, outgoing packets to NAI's SecureCast servers (2000)
    383,  # HP data alarm manager
    384,  # A Remote Network Server System
    387,  # AURP (AppleTalk Update-based Routing Protocol)
    # 389, # Lightweight Directory Access Protocol (LDAP)
    399,  # Digital Equipment Corporation DECnet (Phase V+) over TCP/IP
    401,  # Uninterruptible power supply (UPS)
    427,  # Service Location Protocol (SLP)
    # 433, # NNSP, part of Network News Transfer Protocol
    434,  # Mobile IP Agent (RFC 5944)
    ####
    443,  # HTTPS
    ####
    444,  # Simple Network Paging Protocol (SNPP), RFC 1568
    # 445, # Microsoft-DS SMB file sharing
    # 464, # Kerberos Change/Set password
    465,  # (TCP) Authenticated SMTP over TLS/SSL (SMTPS) / URL Rendezvous Directory for SSM (Cisco protocol)
    # 497, # Retrospect - backup software
    500,  # Internet Security Association and Key Management Protocol (ISAKMP) / Internet Key Exchange (IKE)
    # 502, # Modbus Protocol
    # 504, # Citadel, multiservice protocol for dedicated clients for the Citadel groupware system
    510,  # FirstClass Protocol (FCP), used by FirstClass client/server groupware system
    512,  # Rexec, Remote Process Execution (IBM rexec)
    513,  # rlogin
    514,  # Remote Shell, used to execute non-interactive commands on a remote system (Remote Shell, rsh, remsh)
    # 515, # Line Printer Daemon (LPD)
    ####
    # 520, # (UDP) Routing Information Protocol (RIP) / (TCP) efs, extended file name server
    # 521, # (UDP) Routing Information Protocol Next Generation (RIPng)
    ####
    524,
    # NetWare Core Protocol (NCP) is used for acceess to primary NetWare server resources, Time Synchronization, etc.
    # 525, # (UDP) Timed, Timeserver
    530,  # Remote procedure call (RPC)
    # 533, # (UDP) netwall, For Emergency Broadcasts
    540,  # Unix-to-Unix Copy Protocol
    546,  # DHCPv6 client
    547,  # DHCPv6 server
    548,  # Apple Filing Protocol (AFP) over TCP
    554,  # Real Time Streaming Protocol (RTSP)
    # 556, # Remotefs, RFS, rfs_server
    # 560, # (UDP) rmonitor, Remote Monitor
    561,  # monitor
    # 563, # NNTP over TLS
    # 587, # email message submission (SMTP)
    593,  # HTTP RPC Ep Map, RPC over HTTP, often used by Distributed COM services and MS Exchange Server
    601,  # Reliable Syslog Service — used for system logging
    604,  # TUNNEL profile, a protocol for BEEP peers to form an application layer tunnel
    623,  # ASF Remote Management and Control Protocol (ASF-RMCP) & IPMI Remote Management Protocol - Monitoring
    # 631, # Internet Printing Protocol (IPP)
    # 636, # Lightweight Directory Access Protocol over TLS/SSL (LDAPS)
    639,  # MSDP, Multicast Source Discovery Protocol
    641,  # SupportSoft Nexus Remote Command (control/listening), a proxy gateway connecting remote control traffic
    643,  # SANity (?)
    ####
    646,  # Label Distribution Protocol (LDP), a routing protocol used in MPLS networks
    ####
    647,  # (TCP) DHCP Failover protocol
    # 648, # (TCP) Registry Registrar Protocol (RRP)
    653,  # SupportSoft Nexus Remote Command (data), a proxy gateway connecting remote control traffic
    # 654, # (TCP) Media Management System (MMS) Media Management Protocol (MMP)
    655,  # Tinc VPN daemon
    657,
    # IBM RMC (Remote monitoring and Control) protocol, used by System p5 AIX Integrated Virtualization Manager (IVM)
    # 660, # Mac OS X Server administration, version 10.4 and earlier
    691,  # (TCP) MS Exchange Routing
    694,  # Linux-HA high-availability heartbeat
    # 698, # (UDP) Optimized Link State Routing (OLSR)
    # 700, # (TCP) Extensible Provisioning Protocol (EPP), a protocol for communication between domain name registries and registrars (RFC 5734)
    701,
    # (TCP) Link Management Protocol (LMP), a protocol that runs between a pair of nodes and is used to manage traffic engineering (TE) links
    702,  # (TCP) IRIS (Internet Registry Information Service) over BEEP (Blocks Extensible Exchange Protocol) RFC 3983
    711,  # (TCP) Cisco Tag Distribution Protocol - being replaced by the MPLS Label Distribution Protocol
    712,  # (TCP) Topology Broadcast based on Reverse-Path Forwarding routing protocol (TBRPF), RFC 3684
    # 749, # Kerberos (protocol) administration
    753,  # Reverse Routing Header (RRH)
    782,  # (UNOFFICIAL) Conserver serial-console management server
    # 783, # (UNOFFICIAL) SpamAssassin spamd daemon
    # 829, # Certificate Management Protocol
    ####
    830,  # NETCONF over SSH
    831,  # NETCONF over BEEP
    832,  # NETCONF for SOAP over HTTPS
    833,  # NETCONF for SOAP over BEEP
    ####
    847,  # (TCP) DHCP Failover protocol
    848,  # Group Domain Of Interpretation (GDOI) protocol
    853,  # DNS over TLS (RFC 7858)
    ####
    861,  # OWAMP control (RFC 4656) one-way active measurement protocol
    862,  # TWAMP control (RFC 5357) two-way
    ####
    873,  # (TCP) rsync file synchronization protocol
    # 902, # (UNOFFICIAL) VMware ESXi
    # 903, # (UNOFFICIAL) (TCP) VMware ESXi
    953,  # BIND remote name daemon control (RNDC)
    981,  # (UNOFFICIAL) Remote HTTPS management for firewall devices running embedded Check Point VPN-1 software
    # 987, # (UNOFFICIAL) Microsoft Remote Web Workplace, a feature of Windows Small Business Server
    # 989, # FTPS Protocol (data), FTP over TLS/SSL
    # 990, # FTPS Protocol (control), FTP over TLS/SSL
    # 991, # Netnews Administration System (NAS)
    ####
    992,  # Telnet protocol over TLS/SSL
    ####
    # 993, # Internet Message Access Protocol over TLS/SSL (IMAPS)
    # 995, # Post Office Protocol 3 over TLS/SSL (POP3S)
    1010,  # (UNOFFICIAL) (TCP) ThinLinc web-based administration interface
    # 1023,# (UNOFFICIAL) z/OS Network File System (NFS) (potentially ports 991–1023)

    ##############################################################################

    1027,  # (UDP) Native IPv6 behind IPv4-to-IPv4 NAT Customer Premises Equipment (6a44)
    1058,  # nim, IBM AIX Network Installation Manager (NIM)
    1059,  # nimreg, IBM AIX Network Installation Manager (NIM)
    1167,  # Cisco IP SLA (Service Assurance Agent)
    1194,  # OpenVPN
    1270,  # Microsoft System Center Operations Manager (SCOM) (formerly Microsoft Operations Manager (MOM)) agent
    1293,  # Internet Protocol Security (IPSec)
    1311,  # (UNOFFICIAL) Dell OpenManage HTTPS
    1344,  # Internet Content Adaptation Protocol
    1352,  # IBM Lotus Notes/Domino (RPC) protocol
    1512,  # Microsoft's Windows Internet Name Service (WINS)
    1527,  # Oracle Net Services, formerly known as SQL*Net
    1589,  # Cisco VLAN Query Protocol (VQP)
    1677,  # Novell GroupWise clients in client/server access mode
    ####
    1701,  # Layer 2 Forwarding Protocol (L2F); Layer 2 Tunneling Protocol (L2TP)
    1707,  # (UNOFFICIAL) L2TP/IPsec, for establish an initial connection
    1723,  # Point-to-Point Tunneling Protocol (PPTP)
    1812,  # RADIUS authentication protocol, radius
    1813,  # RADIUS accounting protocol, radius-acct
    ####
    1883,  # MQTT (formerly MQ Telemetry Transport)
    # 1900, # Simple Service Discovery Protocol (SSDP), discovery of UPnP devices
    1967,  # (UNOFFICIAL) Cisco IOS IP Service Level Agreements (IP SLAs) Control Protocol
    1984,  # Big Brother
    ####
    1985,  # Cisco Hot Standby Router Protocol (HSRP)
    1998,  # Cisco X.25 over TCP (XOT) service
    2000,  # Cisco Skinny Client Control Protocol (SCCP)
    # 2049, # Network File System (NFS)
    2083,  # Secure RADIUS Service (radsec)
    2159,  # GDB remote debug port
    2375,  # Docker REST API (plain)
    2376,  # Docker REST API (SSL)
    2377,  # Docker Swarm cluster management communications
    2379,  # CoreOS etcd client communication
    2380,  # CoreOS etcd server communication
    2404,
    # IEC 60870-5-104, used to send electric power telecontrol messages between two systems via directly connected data circuits
    2447,  # ovwdb—OpenView Network Node Manager (NNM) daemon
    2535,  # Multicast Address Dynamic Client Allocation Protocol (MADCAP). All standard messages are UDP datagrams.
    2598,
    # (UNOFFICIAL) Citrix Independent Computing Architecture (ICA) with Session Reliability; port 1494 without session reliability
    # 3020, # Common Internet File System (CIFS). See also port 445 for Server Message Block (SMB), a dialect of CIFS.
    3128,  # (UNOFFICIAL) Squid caching web proxy
    3396,  # Novell NDPS Printer Agent
    ####
    3478,
    # STUN, a protocol for NAT traversal; TURN, a protocol for NAT traversal (extension to STUN); STUN Behavior Discovery. See also port 5349.
    3493,  # Network UPS Tools (NUT)
    ####
    # 3544, # (UDP) Teredo tunneling
    ####
    3667,  # Information Exchange (?)
    # 3799, # (UDP) RADIUS change of authorization
    4321,  # (TCP) Referral Whois (RWhois) Protocol
    4444,  # (UNOFFICIAL) Metasploit's default listener port
    ####
    4500,  # IPSec NAT Traversal (RFC 3947, RFC 4306)
    ####
    4739,  # IP Flow Information Export
    ####
    # 4840, # OPC UA Connection Protocol (TCP) and OPC UA Multicast Datagram Protocol (UDP) for OPC Unified Architecture from OPC Foundation
    # 4843, # OPC UA TCP Protocol over TLS/SSL for OPC Unified Architecture from OPC Foundation
    4949,  # Munin Resource Monitoring Tool
    5000,  # VTun, VPN Software
    ####
    5001,  # (UNOFFICIAL) Iperf (Tool for measuring TCP and UDP bandwidth performance)
    ####
    # 5004, # Real-time Transport Protocol media data (RTP) (RFC 3551, RFC 4571)
    # 5005, # Real-time Transport Protocol control protocol (RTCP) (RFC 3551, RFC 4571)
    5060,  # Session Initiation Protocol (SIP)
    5061,  # (TCP) Session Initiation Protocol (SIP) over TLS
    5201,  # (UNOFFICIAL) Iperf3 (Tool for measuring TCP and UDP bandwidth performance)
    # 5223, # (UNOFFICIAL) Apple Push Notification Service; Extensible Messaging and Presence Protocol (XMPP) client connection over SSL
    # 5242, # (UNOFFICIAL) Viber
    # 5243, # (UNOFFICIAL) Viber
    # 5246, # (UDP) Control And Provisioning of Wireless Access Points (CAPWAP) CAPWAP control
    # 5247, # (UDP) Control And Provisioning of Wireless Access Points (CAPWAP) CAPWAP data
    # 5281, # (UNOFFICIAL) Extensible Messaging and Presence Protocol (XMPP)
    # 5298, # Extensible Messaging and Presence Protocol (XMPP)
    ####
    5349,
    # STUN over TLS/DTLS, a protocol for NAT traversal; TURN over TLS/DTLS, a protocol for NAT traversal; STUN Behavior Discovery over TLS. See also port 3478.
    5351,
    # NAT Port Mapping Protocol and Port Control Protocol—client-requested configuration for connections through network address translators and firewalls
    ####
    5353,  # Multicast DNS (mDNS)
    5402,  # Multicast File Transfer Protocol (MFTP)
    ####
    # 5445, # (UNOFFICIAL) (UDP) Cisco Unified Video Advantage
    5500,  # (UNOFFICIAL) VNC Remote Frame Buffer RFB protocol—for incoming listening viewer
    5568,  # Session Data Transport (SDT), a part of Architecture for Control Networks (ACN)
    # 5678, # (UDP) (UNOFFICIAL) Mikrotik RouterOS Neighbor Discovery Protocol (MNDP)
    5723,  # (UNOFFICIAL) System Center Operations Manager
    5724,  # (UNOFFICIAL) Operations Manager Console
    5800,  # (UNOFFICIAL) VNC Remote Frame Buffer RFB protocol over HTTP
    5900,  # (UNOFFICIAL) Virtual Network Computing (VNC) Remote Frame Buffer RFB protocol
    5938,  # (UNOFFICIAL) TeamViewer remote desktop protocol
    6159,  # ARINC 840 EFB Application Control Interface
    6389,  # (UNOFFICIAL) EMC CLARiiON
    ####
    6513,  # NETCONF over TLS
    6514,  # Syslog over TLS (RFC 5424)
    ####
    6556,  # (UNOFFICIAL) Check MK Agent
    6566,  # SANE (Scanner Access Now Easy)—SANE network scanner daemon
    6600,  # Microsoft Hyper-V Live
    #####
    6653,  # OpenFlow
    #####
    7262,  # CNAP (Calypso Network Access Protocol)
    7272,  # WatchMe - WatchMe Monitoring
    ####
    7547,  # CPE WAN Management Protocol (CWMP), TR-069 (https://en.wikipedia.org/wiki/TR-069)
    ####
    8008,  # Alternative port for HTTP
    8080,  # Alternative port for HTTP
    8089,  # (UNOFFICIAL) Fritz!Box automatic TR-069 configuration
    # 8116, # (UDP) (UNOFFICIAL) Check Point Cluster Control Protocol
    # 8332, # (UNOFFICIAL) Bitcoin JSON-RPC server
    # 8333, # (UNOFFICIAL) Bitcoin; VMware VI Web Access via HTTPS
    8388,  # (UNOFFICIAL) Shadowsocks proxy server
    8443,  # (UNOFFICIAL) Apache Tomcat SSL; Promise WebPAM SSL; iCal over SSL; SW Soft Plesk Control Panel
    8580,  # (UNOFFICIAL) Freegate, an Internet anonymizer and proxy tool
    8834,  # (UNOFFICIAL) Nessus, a vulnerability scanner – remote XML-RPC web server
    8883,  # Secure MQTT (MQTT over TLS)
    # 9000, # (UNOFFICIAL) PHP-FPM default port
    ####
    9001,  # (UNOFFICIAL) cisco-xremote router configuration; Tor network default
    ####
    9030,  # (UNOFFICIAL) Tor
    9050,  # (UNOFFICIAL) Tor
    9051,  # (UNOFFICIAL) Tor
    9100,  # PDL Data Stream, used for printing to certain network printers
    9150,  # (UNOFFICIAL) Tor
    # 9418, # git, Git pack transfer service
    # 9600, # (UDP) (UNOFFICIAL) Factory Interface Network Service (FINS), a network protocol used by Omron programmable logic controllers
    9695,  # Content centric networking (CCN, CCNx)
    # 9899, # (UDP) SCTP tunneling (port number used in SCTP packets encapsulated in UDP, RFC 6951)
    10000,  # Network Data Management Protocol
    10514,  # (UNOFFICIAL) TLS-enabled Rsyslog (default by convention)
    12201,  # (UNOFFICIAL) Graylog Extended Log Format (GELF)
    12345,  # (UNOFFICIAL) NetBus remote administration tool (often Trojan horse)
    13724,  # Symantec Network Utility—vnetd (formerly VERITAS)
    16000,  # (UNOFFICIAL) shroudBNC
    ####
    # 16384, # (UDP) (UNOFFICIAL) CISCO Default RTP MIN

    # 16482, # (UDP) (UNOFFICIAL) CISCO Default RTP MAX
    ####
    19226,  # (UNOFFICIAL) Panda Software AdminSecure Communication Agent
    19999,
    # Distributed Network Protocol—Secure (DNP—Secure), a secure version of the protocol used in SCADA systems between communicating RTU's and IED's
    20000,  # Distributed Network Protocol (DNP), a protocol used in SCADA systems between communicating RTU's and IED's
    # 24554, # BINKP, Fidonet mail transfers over TCP/IP
    31416,  # (UNOFFICIAL) BOINC RPC
    32137,  # (UNOFFICIAL) Immunet Protect (UDP in version 2.0, TCP since version 3.0)
    # 33434, # traceroute
    # 35357, # OpenStack Identity (Keystone) administration
    # 37008, # (UDP) (UNOFFICIAL) TZSP intrusion detection
    40000,  # SafetyNET p – a real-time Industrial Ethernet protocol
    44818,  # EtherNet/IP explicit messaging
    # 47001, # Windows Remote Management Service (WinRM)
    # 47808, # BACnet Building Automation and Control Networks (4780810 = BAC016)

    # 49151  # RESERVED

    # The range 49152–65535 (2^15 + 2^14 to 2^16 − 1) contains dynamic or private ports that cannot be registered with IANA.
    # This range is used for private or customized services, for temporary purposes, and for automatic allocation of ephemeral ports.
    # https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
]
