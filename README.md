# IP Sibling Detection on Public Network Devices

*IP Sibling Detection Toolset*

## Python Dependencies

* [scapy](https://scapy.readthedocs.io/en/latest/)
* [netifaces](https://github.com/al45tair/netifaces)
* [ipaddress](https://docs.python.org/3/library/ipaddress.html)
* [numpy](https://docs.scipy.org/doc/numpy/)
* [scipy](https://docs.scipy.org/doc/scipy/reference/)
* [pandas](https://pandas.pydata.org/pandas-docs/stable/)
* [matplotlib](https://matplotlib.org/contents.html)
* [prettytable](https://ptable.readthedocs.io/en/latest/index.html)
* [geoip2](https://geoip2.readthedocs.io/en/latest/)
* [sklearn](https://scikit-learn.org/stable/documentation.html)
* [xgboost](https://xgboost.readthedocs.io/en/latest/)

Everything works with versions published within 2018.


## Usage Message

```
usage: ipsiblings [-h] [-d BASE_DIR] [--run-id RUN_ID] [--export-plots] [--evaluator {TCPRAW_SCHEITLE,TCPRAW_STARKE,DOMAIN,SSH_KEYSCAN,TCP_OPTIONS,ML_STARKE,BITCOIN}]
                  [--skip-evaluator {TCPRAW_SCHEITLE,TCPRAW_STARKE,DOMAIN,SSH_KEYSCAN,TCP_OPTIONS,ML_STARKE,BITCOIN}] [--eval-batch-size EVAL_BATCH_SIZE] [--eval-fail-fast]
                  [--eval-ssh-timeout EVAL_SSH_TIMEOUT] [--eval-first-batch EVAL_FIRST_BATCH] [--eval-batch-count EVAL_BATCH_COUNT] [--skip-eval] [--only-init] [-v | -q]
                  [--targets-from {BITCOIN,FILESYSTEM}] [--skip-v SKIP_V] [--from START_INDEX] [--to END_INDEX] [--do-harvest] [--really-harvest] [--harvester {TCP_TS,BTC}] [-hd HARVEST_DURATION]
                  [-ti TS_INTERVAL] [-bi BTC_INTERVAL] [-ttr TS_TIMEOUT] [-htf HARVEST_TIMEOUT_FINAL] [--skip-os-sysctls] [--skip-os-iptables] [--skip-os-ntp]

IP Siblings Toolset

optional arguments:
  -h, --help            show this help message and exit

PATHS:
  -d BASE_DIR, --base-dir BASE_DIR
                        Base directory for application data (default ./target)
  --run-id RUN_ID       Identifier for the run to contribute to, appended to the base directory. (default current date-time)

EVALUATION:
  --export-plots        Export plots after evaluation
  --evaluator {TCPRAW_SCHEITLE,TCPRAW_STARKE,DOMAIN,SSH_KEYSCAN,TCP_OPTIONS,ML_STARKE,BITCOIN}
                        Select a specific evaluator instead of running all of them. May be specified multiple times.
  --skip-evaluator {TCPRAW_SCHEITLE,TCPRAW_STARKE,DOMAIN,SSH_KEYSCAN,TCP_OPTIONS,ML_STARKE,BITCOIN}
                        Skip a specific evaluator. May be specified multiple times.
  --eval-batch-size EVAL_BATCH_SIZE
                        Candidates to evaluate per batch (default 10_000)
  --eval-fail-fast      Exit immediately upon the first evaluation exception.
  --eval-ssh-timeout EVAL_SSH_TIMEOUT
                        Timeout in seconds per batch for SSH keyscan, default 60.
  --eval-first-batch EVAL_FIRST_BATCH
                        Start counting eval batches at this number, default 0.
  --eval-batch-count EVAL_BATCH_COUNT
                        How many batches to evaluate, default all.

SKIP STEPS:
  --skip-eval           Skip any interpretation of collected data
  --only-init           Exit after loading configuration

LOGGING:
  -v, --verbose         Increase verbosity once per call
  -q, --quiet           Decrease verbosity once per call

TARGET NODES:
  --targets-from {BITCOIN,FILESYSTEM}
                        Where to get target nodes from (default TargetProviderChoice.BITCOIN)
  --skip-v SKIP_V       Skip IPvX addresses while acquiring targets (for testing, may be specified multiple times, ignored for filesystem provider)
  --from START_INDEX    Index of first target to consider (default 0)
  --to END_INDEX        Index of first target to skip (default none)

TIMESTAMP COLLECTION:
  --do-harvest          Collect (harvest) if no timestamps present
  --really-harvest      Harvest even if we already have timestamps
  --harvester {TCP_TS,BTC}
                        Select a specific harvester instead of running all of them. May be specified multiple times.
  -hd HARVEST_DURATION, --harvest-duration HARVEST_DURATION
                        Collection duration, seconds (default 36000)
  -ti TS_INTERVAL, --ts-interval TS_INTERVAL
                        Collection interval for timestamps per target, seconds (default 60)
  -bi BTC_INTERVAL, --btc-interval BTC_INTERVAL
                        Collection interval for Bitcoin protocol per target, seconds (default 1800 / 30min)
  -ttr TS_TIMEOUT, --ts-timeout TS_TIMEOUT
                        Wait at least this many seconds for timestamp replies per iteration (Should not be longer than -thi) (default 20)
  -htf HARVEST_TIMEOUT_FINAL, --harvest-timeout-final HARVEST_TIMEOUT_FINAL
                        Wait at least this long for replies after the last iteration (default 120)

OPERATING SYSTEM SETTINGS:
  By default, we adapt some global (!!) OS settings. The previous values are saved to ./settings.bak and restored when the application exits.

  --skip-os-sysctls     Skip overwriting necessary sysctls
  --skip-os-iptables    Skip adding necessary iptables rules
  --skip-os-ntp         Skip disabling NTP client

```

## Architecture
description TBD, but trust me there is one

## Files `scripts/`
Old scripts related to Starke's work.

`gt_api_scripts/`: API interaction scripts to compile ground truth host list  
`run/`: Bash scripts to handle batches of data  
`xpref6/`: IPv6 routing prefix extraction from publicly available routing data  
`load_cdn_ipnets.py`: Extendable script to compile CDN filter list  
`min_ts_ssh.py`: PoC for FreeBSD timestamp acquisition with only one TCP connection  
`resolve_toplist_domains.py`: Resolution of domain Top List files  
`xgb_print_features.py`: Script to reproduce plots in the thesis (contains used data)

## Execution
For measurement, you need a dual-stack server with sufficient bandwidth
and at least 1 GB of RAM. It is advised to enable at least 2 GB of swap (file-based is fine)
to handle spikes due to other applications -- you don't want a ten-hour run to be OOM-killed
at the ninth hour.

For evaluation, more resources are necessary. It is technically possible to evaluate on a
low-end host such as the one suggested for measurement above, but you need to specify
a very low batch size (10k or less) and it will take a long time, producing many
batches that need to be merged. Note that, at the time of writing, the Bitcoin
network consists of around 6k v4 nodes and 1.5k v6 nodes, which results in
around 6 million (!!) candidates for evaluation. For this work,
a Linux server with 16 GB of RAM was used. Note that evaluation is single-threaded and
performance may be improved by having multiple processes responsible for different
batch numbers.


## File Formats
Data is stored in tab-separated values (TSV) files. The reason for this
is that we have nested lists which we want to separate using a reasonable
separator. The separator hierarchy is TAB, `,`, `:`.

Target information for the `filesystem` target provider is stored using
tuples of the following format:

| Field                  | Example                                  | Description                                                                                                                                                                                                                            |   |   |
|------------------------|------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---|---|
| * IP Version           | 4                                        | IP Version of the address                                                                                                                                                                                                              |   |   |
| * IP Address           | 127.0.0.1                                | Target IP address                                                                                                                                                                                                                      |   |   |
| * Port                 | 8333                                     | Target TCP port                                                                                                                                                                                                                        |   |   |
| Target Domains         | bitcoin.example.com,bitcoin2.example.com | Domains known to be associated with this target, comma-separated.                                                                                                                                                                      |   |   |
| TCP Options            | Timestamp:1234:0,MSS:1024                | TCP Options captured with the first harvested timestamp, comma-separated. The constant string `--None--` if absent. Multiple values for the same option are separated by colons, and the first field is always the name of the option. |   |   |
| ...TSval               | 1234                                     | First captured TCP timestamp value for this target, integer as returned by the TCP stack. The granularity of this varies and is not defined by the standard.                                                                           |   |   |
| ...Reception Timestamp | 34132453.567                             | Reception timestamp populated by our TCP stack, in seconds since the Unix epoch, with fractional values.                                                                                                                               |   |   |
| ...                    |                                          | The last two fields (marked with `...`) are repeated for every received timestamp.  


## Execution
via pip/setuptools:

```bash
python3 -m pip install -e .
```

## Distribution
As per https://packaging.python.org/tutorials/packaging-projects/.

Increment the version number in `setup.py`.
Then run `./local_install.sh`.

You can deploy this to a Linux server using the `remote_install.sh` script.
Note that you need to have `python3 python3-venv cmake` installed
on the remote server if it is running Debian.

Further, for Python-Bitcoinlib, we need the `libssl-dev` package.

## Why we need root access
It is desirable for the measuring platform not to run as root user.

For raw socket access, we could use `CAP_NET_RAW`, passed to the
Python process via ambient capabilities, as described
[here](https://stackoverflow.com/a/47982075/1117552).
We could provide a C/Rust/CPython binary wrapper that does
this, since we do not want the general Python executable
(even of a venv) to have that capability, which allows to
read and write ALL network traffic of the system.

**However,** we cannot modify sysctl values if we are not root,
which means we'd need to move that logic into the wrapper as
well, and also have the wrapper setuid to root, which
is an improvement but still not the best. Further, the
OS settings logic is complex enough that we wouldn't want
it to be written in C if avoidable.

Hence, for the time being, we still require to be run as root.

## Links

[Scapy](https://scapy.net/)  
[XGBoost](https://github.com/dmlc/xgboost)  
[scikit-learn](https://scikit-learn.org/stable/index.html)  
[NumPy](https://www.numpy.org/)  
[SciPy](https://www.scipy.org/)  
[pandas](https://pandas.pydata.org/)  
[MaxMind GeoLite2](https://dev.maxmind.com/geoip/geoip2/geolite2/)  

This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com.

## TODOs

* Load already prepared machine learning models within `SiblingCandidate` and `LowRTSiblingCandidate` classes (`evaluate()` function) in `ipsiblings/libsiblings.py` to implement prediction as done in `ipsiblings/evaluation.py`
* Reduce disk space and access times by working with a database instead of text files
* Combine all functionalities in one file as a module
  - Check only one target at a time
  - Eliminate preprocessing like tracerouting etc. from the one-file-module
