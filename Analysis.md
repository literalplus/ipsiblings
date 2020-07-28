Analysis of existing codebase
=============================

## General mood

 * Code is not formatted consistently, PEP-8 violations
 as well as 298 Sonar issues
 * Most of these are related to bad segmentation -
 files and methods do too much, which makes the project difficult to grasp and maintain
 * License is apparently GPLv3 (`__init__.py`) -- however, some code seems to be borrowed with other licenses
 * Exception handling does not seem overly sophisticated, often these
 are just ignored, or general `except` clauses are used
 * Project structure is unclear

## Next steps

 1. We will want to replace/extend the Alexa top list implementations with/by the Bitcoin nodes script.
 The current code also seems to support loading from a list of IPs in a file, but since we already have it in
 Python anyways, might as well integrate it properly.
 2. Actually try running the application against a subset of the Bitcoin nodes.
 3. Split up `main.py` into a separate module per concern
 4. Further analysis of `libsiblings`, move evaluation logic into a dedicated class
 5. Reconsider module separation based on actual data flow & dependencies
 6. From README: Consider using a database of some sort (which one? benefits at this point?)

Detailed analysis per file
==========================

## `main.py`
A 1k line file that sets up everything and seems
to power a multitude of different use-cases.

 * Argument parsing and configuration management
 should be moved into a separate file for clarity
 * Arguments should not be stored in local variables,
 but in clear data structures depending on the
 use-case
 * Handling of global state should be explicit
 * Actual bootstrap logic for the different use-cases
 should be split into independent modules
 * This file does way too much.

This file handles:

 * Argument parsing
 * Log levels
 * Loading of Alexa toplist if necessary
 * Partitioning via start/end index
 * Setup of Geolocation
 * IP Interface detection + metadata
 * IP blacklist creation via `libtools`
 * Either:
   * Loading of trace sets, or
   * Loading of targets, and
      * Writing of candidate pairs if requested, and exit, otherwise
      * Processing of targets:
         * CDN filter
         * Invocation of traceroute for trace sets (`libtraceroute`)
         * Invocation of actual traces (`libtrace`)
         * Trace retry / max logic
         * Port scanning via `libts.TraceSetPortScan`
         * Writing of trace sets via `libtrace`
   * or: Loading of candidates file via `libts.load_candidate_pairs`, and:
      * Port scanning if missing via `libts.CandidatePortScan`
      * Writing of candidate where port scans are still missing
 * Determination of active nodes
 * If requested and no candidates available:
   * Harvesting via `libts.TraceSetHarvester`
   * Writing of harvested timestamp data
 * If requested and candidates available:
   * Harvesting via `CandidateHarvester`
   * Writing of candidate pairs with timestamp data
 * If requested, evaluation:
   * Construction of sibling candidates if timestamp data available (otherwise exit)
   * Invocation of SSH keyscan, exit if we only wanted this
   * Candidate evaluation via `SiblingCandidate.evaluate()`
   * Writing of candidate results, if requested
   * Plotting of candidates' traces to a PDF file
 * If no result file and no plotting happened, exit
 * Testing:
   * Take a random sibling candidate
   * If not sibling, bail
   * Otherwise, print some stats for this candidate
 * Done.

Further:

 * Check if dependencies are present
 * Optimise OS settings
 * Disable NTP
 * Apply firewall rules

## `libtools`
Miscellaneous unrelated tooling.

 * At least `network.py` belongs somewhere else
 * Some implementations seem to be taken from Internet sources,
 not sure if these use GPLv3 compatible licenses.
 * `except: pass` is used on multiple occasions
 * some duplicated and overly complex code

## `resolved.py`
Manages Alexa toplist.

This works like:

 * Entrypoint: `load_toplist_file`
 * self.toplist is keyed by position, value is domain
 * If no file specified and remote loading enabled, load toplist from remote URL
 * otherwise, load toplist from a CSV file

Resolved domains:

 * Stored in a file of `domain -> [set(ipv4), set(ipv6)]`
 * Loaded on startup if provided
 * Can also save unresolvable domains to a file
 * Resolve via `resolve_toplist`, however this takes forever so
 it is recommended to do this via a Go script
 (i.e. why is the Python implementation still present?)
 
Targets:

 * `construct_targets()` builds `(domains, v4, v6)` tuples that
 serve as target candidates
 * Operates only on resolved domains
 * `construct_candidates()` works the same, but builds a dict
 of `CandidatePair` objects

## `cdnfilter.py`
Keeps track of the CDN filter.

 * Some methods here are too complex
 * the `filter` method does not seem to be used

## `evaluation.py`
Complex mix of tools to evaluate results.

 * File has 1.5k lines, should be cleaned up if it were to be used
 * Large blocks of commented code
 * Concrete functionality is unclear due to complexity

## `keyscan.py`
Probes hosts with open SSH ports for their host keys, using
an external process of `ssh-keyscan`. Runs a thread for each
address family.

 * Complex functions and duplicated code

## `libconstants.py`
Keeps constants and global variables.

 * Keeping global variables is an anti-pattern
 * This file does too much

## `libgeo.py`
Handles reading from a Geo-IP database and updating thereof.

 * Unusually many comments / commented code, `asn` method is unused, `city` method returns something else
 * Data is represented as a dict with string keys, even though the structure seems static

## `liblog.py`
Wraps interaction with the `logging` package.

 * Could be part of `libtools`, it is a utility after all (-> Clear module structure / See high.level structure of
 project immediately)
 
## `libsiblings.py`
Various utilities and logic for sibling evaluation, essentially the core business logic of the application.

```
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
```

 * It is left unclear which portions of this file are taken from Scheitle et al.
 * This file does too much - 1997 lines (!!!) - split a little, but needs more work
 * A lot of methods have very high cognitive complexity, making them hard to understand
 * SiblingCandidate class definitely does too much:
   * Plotting
   * Features for Machine Learning
   * Actual evaluation + calculation of properties
 * LowRTSiblingCandidate duplicates a lot of code from its superclass - design for extension instead!

Logic analysis TBD

## `libtrace.py`
Handles interaction with traces.

 * This file does too much - 997 lines, split

## `libtraceroute.py`
Takes trace routes of candidates using different algorithms.

## `libts.py`
"Harvests" candidate pairs via a port scan and connecting to open TCP ports.

 * 1165 lines, does too much - split

## `settings.py`
Sets up OS settings, backs them up to a file, and restores them later.

## `stats.py`
Extracts statistics from data directory.
