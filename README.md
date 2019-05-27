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

## Important Notes

Recent versions of scipy's `LSQUnivariateSpline` allow **strictly increasing** x
values only.
Due to internal design decisions we require **increasing** sequences.
This means the file `scipy/interpolate/fitpack2.py` must be patched.
To do so change `if not np.all(diff(x) > 0.0):` to `if not np.all(diff(x) >= 0.0):` in the initialization of the `LSQUnivariateSpline` class.
You may also simply comment the dependency check in the `main.py` file.


## Usage Message main.py

```
usage: main.py
               (-c [CANDIDATES] | -t [TRACE_TARGETS] | -l | --alexa-toplist [ALEXA_TOPLIST_DIR] | --debug)
               [-h] [-d DIRECTORY] [-i IGNORE_FILE] [-r] [-s]
               [-f RESOLVED_FILE] [-o] [--router-ports] [--server-ports]
               [--from START_INDEX] [--to END_INDEX] [--low-runtime] [--print]
               [--resultfile [RESULTFILE]] [--no-evaluation]
               [--cdn-file CDN_FILE] [--write-pairs [WRITE_PAIRS]]
               [--no-ssh-keyscan] [--only-ssh-keyscan] [-v | -q]
               [--city-db CITY_DB] [--asn-db ASN_DB] [--update-geo-dbs]

IP Siblings Toolset

The argument of -c/-t option (combined with -s option) can be used with alexa
top list file if resolution is required.
[Any other file formatted in that way can be used.]

required argument, exactly one:
  -c [CANDIDATES], --candidates [CANDIDATES]
                        parse candidates from csv file or top list (-s)
  -t [TRACE_TARGETS], --trace-targets [TRACE_TARGETS]
                        trace target hosts from csv file or top list (-s)
  -l, --load            load previously saved trace sets from base directory
  --alexa-toplist [ALEXA_TOPLIST_DIR]
                        loads the alexa top list from the internet and saves
                        it to the given directory or current working directory
  --debug               debug run (only run initialization)

optional arguments:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        base directory to store and load trace sets
  -i IGNORE_FILE, --ignore-file IGNORE_FILE
                        nodes to ignore are listed in this file
  -r, --run-harvest     perform harvesting for candidate IPs
  -s, --resolved        construct candidates or trace targets from resolved
                        (alexa top) list (use with -c/-t for operation mode)
  -f RESOLVED_FILE, --resolved-file RESOLVED_FILE
                        csv file holding resolved (alexa) domains and IPs
  -o, --download-alexa  allows downloading alexa top list from the internet
  --router-ports        use the comprehensive port list for non-server devices
  --server-ports        use the much smaller port list for servers
  --from START_INDEX    restricts candidates/targets to a start index
  --to END_INDEX        restricts candidates/targets to an end index
                        (excluded)
  --low-runtime         use only few timestamps for evaluation
  --print               print charts to pdf file
  --resultfile [RESULTFILE]
                        write evaluation results to file
  --no-evaluation       do not perform any calculations/evaluations on sibling
                        candidates
  --cdn-file CDN_FILE   load CDN networks for IP filtering
  --write-pairs [WRITE_PAIRS]
                        write constructed IP pairs to file
  --no-ssh-keyscan      do not scan for public ssh keys
  --only-ssh-keyscan    exit after keyscan

optional logging arguments:
  -v, --verbose         increase verbosity once per call
  -q, --quiet           decrease verbosity once per call

optional geolocation arguments:
  --city-db CITY_DB     custom MaxMind city database
  --asn-db ASN_DB       custom MaxMind ASN database
  --update-geo-dbs      update geolocation databases
```

## Files `ipsiblings/`

`libconstants.py`: Global settings and parameter configurations  
`settings.py`: Handling of OS specific prerequisites for acquisition tasks  
`liblog.py`: Logging facility  
`main.py`: CLI parsing and executional tasks  
`libtools.py`: Contains necessary and useful functions  
`resolved.py`: Deals with Top Lists and domain resolution  
`algorithms/`: Directory holding different traceroute algorithms  
`libalgorithm.py`: Register new traceroute algorithms here  
`cdnfilter.py`: Filter targets within CDN networks based on provided IP network list  
`libtraceroute.py`: Traceroute logic  
`libtrace.py`: Trace Set and Trace objects and structures  
`libts.py`: Port scanning and acquisition tasks  
`libsiblings.py`: Represents a sibling candidate and corresponding functions  
`libgeo.py`: Geolocation service interface and related functions  
`keyscan.py`: SSH keys and agents acquisition  
`stats.py`: Statistics  
`evaluation.py`: Functions used for model construction and evaluation

## Files `scripts/`

`gt_api_scripts/`: API interaction scripts to compile ground truth host list  
`run/`: Bash scripts to handle batches of data  
`xpref6/`: IPv6 routing prefix extraction from publicly available routing data  
`load_cdn_ipnets.py`: Extendable script to compile CDN filter list  
`min_ts_ssh.py`: PoC for FreeBSD timestamp acquisition with only one TCP connection  
`resolve_toplist_domains.py`: Resolution of domain Top List files  
`xgb_print_features.py`: Script to reproduce plots in the thesis (contains used data)


## Execution Notes

It is necessary to implement the proposed model evaluation in the `SiblingCandidate.evaluate()` function for the `--resultfile` switch to work properly. Due to lack of time we extended our initial investigational approach in the `evaluate.py` script for the final results discussed in our thesis but we still did not move the decision logic to the intended function. All required materials for this are available within the repository (models*.pickle, code in `evaluate.py`, etc.).

#### Workflow
1. Domain resolution with `scripts/resolve_toplist_domains.py` (and some text processing)


2. Executing toolset to traceroute and port scan resolved targets
3. Timestamp acquisition


4. Evaluation
  * With `ipsiblings/evaluation.py` and respective functions
  * Or by updating the `evaluate()` function in `SiblingCandidate` classes in `ipsiblings/libsiblings.py` and implementing the usage of the proposed model (as in `evaluation.py`)

Step 1 is handled by the script.  
Step 2 and 3 are performed by calling `main.py` with appropriate parameters.  
Step 4 is carried out by applying functions contained in the evaluation script or updating the respective classes.

#### Execution Examples

* Initially execute low-runtime tracerouting for given targets and port scanning for active nodes  
  `./main.py -t -sf targets_resolved.csv -d /root/datadir -i ignore.txt -vv --low-runtime --router-ports --cdn-file cdn_nets.txt`
* Load previously saved trace sets and run harvesting without ssh-keyscan  
  `./main.py -ld /root/datadir -i ignore.txt -vv -r --low-runtime --no-ssh-keyscan`
* Perform port scan and full-runtime harvesting on given candidates and print charts and write results to file  
  `./main.py -c candidates.csv -i ignore.txt -vv -r --print --resultfile`  
  (`--print` is only available with full-runtime data; `--resultfile` needs implementation of `evaluate()` function)


## File Formats

##### Hostlists: `domain,ip4,ip6`

##### Candidate Pairs: `ip4;ip4ports;ip6;ip6ports;domains`
Example: `192.168.42.42;22,80;2001:db8:0:ff00::42;22,80;domain1.com,domain2.com`

##### TCP Options: `ip,option:value,option:value1:value2, ...`
Example: `192.168.0.42,MSS:1460,NOP:None,NOP:None,Timestamp:356986792:1337,NOP:None,WScale:7`

##### Timestamp Data:
```
ip
port_A,tcp_ts_X,received_ts_X,tcp_ts_Y,received_ts_Y, ...
port_B,tcp_ts_I,received_ts_I,tcp_ts_J,received_ts_J, ...
<LF>
```
IPv4 and IPv6 separated by `<LF><LF> = <LF><LF>`  
Example:
```
192.168.4.2
53,2834518011,1546891762.097881,2834519211,1546891763.297063
443,2834518039,1546891762.125485,2834519439,1546891763.525016
80,2834520208,1546891764.296607,2834522208,1546891766.296377

=

2001:db8:ff00::4
22,357063953,1546891762.880278,357065703,1546891769.879826
80,357064417,1546891764.735809,357064917,1546891766.735792
```

##### SSH-Agents: `ip;identification_string`
IPv4 and IPv6 separated by `<LF><LF> = <LF><LF>`  
Exapmle:
```
192.168.0.42;SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8

=

2001:db8:42::4;SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
```

SSH-Keys: `ip key-type key`  
Example: `192.168.4.2 ssh-ed25519 AAAAPT4gV0UgTE9WRSBBTklNQUxTIDw9IHwgPT4gV0UgTE9WRSBBTklNQUxTIDw9Cg==`

##### CDN Filter: `ip/netsize`  
Example:
```
# this is a comment
192.168.0.0/16
2001:db8::/32
```

##### IP Ignore File:
IPv4 and IPv6 separated by `<LF> = <LF>`  
```
# comment
192.168.0.42
=
# here starts v6 section
2001:db8::42
```


## Trace Sets and Traces

A Trace Set is identified based on a unique ID which refers to the MD5 hash of the IPv4 and IPv6 traceroute targets combined to a string of the form `ip4_ip6`.
Each Trace Set can hold multiple distinct Traces.
Traces within such a set are identified by their own unique ID based on an MD5 hash of the IPv4 and IPv6 traceroute target, the IP addresses of the IPv4 traceroute as well as the IPv6 traceroute and the IPv4 and IPv6 traceroute lengths.
This ensures that distinct traceroutes can be easily identified.
```python
# Trace Set ID
def _id(self):
  str_to_hash = '{0}_{1}'.format(self.target[0], self.target[1])
  h = hashlib.md5()
  h.update(str_to_hash.encode('utf-8'))
  return h.hexdigest()

# Trace ID
def _id(self):
  h = hashlib.md5()
  h.update(self.v4target.encode('utf-8'))
  h.update(self.v6target.encode('utf-8'))
  for ip in self.v4trace:
    h.update(ip.encode('utf-8'))
  for ip in self.v6trace:
    h.update(ip.encode('utf-8'))
  h.update(str(self.v4length).encode('utf-8'))
  h.update(str(self.v6length).encode('utf-8'))
  return h.hexdigest()
```

Trace Sets are logically represented by a folder named with the Trace Set ID.
Within this folder the files are named according to their purpose and with the trace ID appended.  
Example:

```
project
└── 003667a665178ad655b2fd22f2843ade
    ├── data.txt
    ├── target.txt
    ├── tcp_options.txt
    ├── trace_2722b0887d809b34efe65ea3ca7b3b9b.active_nodes.txt
    ├── trace_2722b0887d809b34efe65ea3ca7b3b9b.active_nodes.txt.pcap
    ├── trace_2722b0887d809b34efe65ea3ca7b3b9b.txt
    ├── trace_6c2740d3fae54fc34277eaa4202a1e69.active_nodes.txt
    ├── trace_6c2740d3fae54fc34277eaa4202a1e69.active_nodes.txt.pcap
    ├── trace_6c2740d3fae54fc34277eaa4202a1e69.txt
    ├── trace_e3859ee72356ce3c7be7182c10c314f7.active_nodes.txt
    ├── trace_e3859ee72356ce3c7be7182c10c314f7.active_nodes.txt.pcap
    └── trace_e3859ee72356ce3c7be7182c10c314f7.txt
```

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
