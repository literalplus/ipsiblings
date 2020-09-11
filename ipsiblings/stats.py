# libsiblings.py
#
# (c) 2019 Marco Starke
#

import csv
import glob
import pathlib

import numpy

from ipsiblings import libsiblings, libtools
from ipsiblings.libtrace import load_trace_sets
from ipsiblings.libts.serialization import load_candidate_pairs
# set field_size_limit() from 131072 (2**17) to 262144 (2**18)
from ipsiblings.preparation import PreparedTraceSets, PreparedPairs

csv.field_size_limit(262144)


def get_number_ssh_agents(file_or_basedir):
    agents = []
    if pathlib.Path(file_or_basedir).is_file():
        with open(file_or_basedir, mode='r') as infile:
            agents.extend(infile.readlines())
        agentsset = set(agents)
    else:
        dirs = glob.glob('{0}/*/ssh-agents.txt'.format(file_or_basedir))
        for dir in dirs:
            with open(dir, mode='r') as infile:
                agents.extend(infile.readlines())
        agentsset = set(agents)

    return len(agentsset)


def get_port_stats_base(basedir):
    tracesets = list(load_trace_sets(basedir, libtools.network.obtain_nic()).values())  # only objects in list
    v4ports = set()
    v6ports = set()
    v4map = {}  # { port: count }
    v6map = {}  # { port: count }
    v4active = 0
    v6active = 0

    for t in tracesets:
        v4p, v6p = t.get_active_nodes()  # ( { IPv4: { portlist } }, { IPv6: { portlist } } )
        for ip, ports in v4p.items():
            v4active = v4active + 1
            for p in ports:
                port = int(p)
                if port in v4map:
                    v4map[port] = v4map[port] + 1
                else:
                    v4map[port] = 1
                v4ports.add(port)
        for ip, ports in v6p.items():
            v6active = v6active + 1
            for p in ports:
                port = int(p)
                if port in v6map:
                    v6map[port] = v6map[port] + 1
                else:
                    v6map[port] = 1
                v6ports.add(port)

    return (v4ports, v6ports, v4map, v6map, v4active, v6active)


def get_port_stats_batches(basedir):
    v4ports = set()
    v6ports = set()
    v4map = {}  # { port: count }
    v6map = {}  # { port: count }
    v4active = 0
    v6active = 0

    bdir = pathlib.Path(basedir)
    for dir in bdir.iterdir():
        if dir.is_dir() and '_traces_' in dir.name:
            v4p, v6p, v4m, v6m, v4a, v6a = get_port_stats_base(dir)  # map: { port: count }
            v4active = v4active + v4a
            v6active = v6active + v6a
            v4ports.update(v4p)
            v6ports.update(v6p)
            for p, count in v4m.items():
                if p in v4map:
                    v4map[p] = v4map[p] + count
                else:
                    v4map[p] = count

            for p, count in v6m.items():
                if p in v6map:
                    v6map[p] = v6map[p] + count
                else:
                    v6map[p] = count

    return (v4ports, v6ports, v4map, v6map, v4active, v6active)


def is_montonically_increasing_check_wraparound(list_of_timestamp_tuples, strict=False):
    arr = numpy.array([x[0] for x in sorted(list_of_timestamp_tuples, key=lambda x: x[1])])
    diff = numpy.diff(arr)
    diffcount = 0
    if strict:
        for d in diff:
            if d <= 0:
                diffcount = diffcount + 1
                if diffcount > 1:  # more than one wraparound not possible during our measurement time (except clock rate is much higher than 1kHz)
                    return False
    else:
        for d in diff:
            if d < 0:
                diffcount = diffcount + 1
                if diffcount > 1:  # more than one wraparound not possible during our measurement time (except clock rate is much higher than 1kHz)
                    return False

    return True


def is_montonically_increasing(list_of_timestamp_tuples, strict=False):
    arr = numpy.array([x[0] for x in sorted(list_of_timestamp_tuples,
                                            key=lambda x: x[1])])  # sort by arrival time, get only received ts
    if strict:
        return numpy.all(arr[1:] > arr[:-1])
    else:
        return numpy.all(arr[1:] >= arr[:-1])


def get_number_of_randomized_nodes_traces(dir, initial_ts_threshold=10000):
    candidates = list(libsiblings.construct_candidates._construct_trace_candidates(
        PreparedTraceSets(load_trace_sets(dir, libtools.network.obtain_nic())), low_runtime=True
    ).values())
    randomized = 0
    nr_nodes = len(candidates)
    for cand in candidates:
        ts4, ts6 = cand.ip4_ts, cand.ip6_ts
        sorted4 = sorted(ts4, key=lambda x: x[1])  # sort by arrival time
        sorted6 = sorted(ts6, key=lambda x: x[1])
        if abs(sorted4[0][0] - sorted6[0][0]) > initial_ts_threshold:
            randomized = randomized + 1
    return (randomized, nr_nodes)


def get_number_of_randomized_nodes_traces_batches(basedir, initial_ts_threshold=10000):
    randomized = 0
    nr_nodes = 0
    bdir = pathlib.Path(basedir)
    for dir in bdir.iterdir():
        if dir.is_dir() and '_traces_' in dir.name:
            rs, nrn = get_number_of_randomized_nodes_traces(dir, initial_ts_threshold=initial_ts_threshold)
            randomized = randomized + rs
            nr_nodes = nr_nodes + nrn
    return randomized, nr_nodes


def get_number_randmized_nodes_candidates(candidate_file, initial_ts_threshold=10000, lrt=True):
    candidates = list(
        libsiblings.construct_candidates._construct_pair_candidates(
            PreparedPairs(load_candidate_pairs(candidate_file)[3], False, 0, False), low_runtime=lrt
        ).values()
    )  # only pairs
    randomized = 0
    nr_nodes = len(candidates)
    for cand in candidates:
        ts4, ts6 = cand.ip4_ts, cand.ip6_ts
        sorted4 = sorted(ts4, key=lambda x: x[1])  # sort by arrival time
        sorted6 = sorted(ts6, key=lambda x: x[1])
        if abs(sorted4[0][0] - sorted6[0][0]) > initial_ts_threshold:
            randomized = randomized + 1

    return (randomized, nr_nodes)


def get_number_randmized_nodes_candidates_batches(basedir, initial_ts_threshold=10000, file_name='candidatepairs.csv'):
    randomnodes = 0
    nr_nodes = 0
    bdir = pathlib.Path(basedir)
    for dir in bdir.iterdir():
        if dir.is_dir() and bdir.parts[-2].lower() in dir.name:
            rs, nrn = get_number_randmized_nodes_candidates(dir / file_name, initial_ts_threshold=initial_ts_threshold)
            randomnodes = randomnodes + rs
            nr_nodes = nr_nodes + nrn

    return (randomnodes, nr_nodes)


def get_path_node_stats(dir, return_sets=False):
    tracesets = list(load_trace_sets(dir, libtools.network.obtain_nic()).values())

    v4nodes = set()
    v6nodes = set()
    v4active = set()
    v6active = set()

    for t in tracesets:
        traces = t.get_traces()
        for trace in traces.values():
            v4, v6 = trace.get_trace_lists()
            v4a, v6a = trace.get_active_nodes()  # ( { IPv4: [ ports ] } , { IPv6: [ ports ]  } )
            v4nodes.update(set(v4))
            v6nodes.update(set(v6))
            v4active.update(set(v4a.keys()))
            v6active.update(set(v6a.keys()))

    if return_sets:
        return (v4nodes, v6nodes, v4active, v6active)
    else:
        return (len(v4nodes), len(v6nodes), len(v4active), len(v6active))


def get_path_node_stats_batches(basedir, return_sets=False):
    v4nodes = set()
    v6nodes = set()
    v4active = set()
    v6active = set()

    bdir = pathlib.Path(basedir)
    for dir in bdir.iterdir():
        if dir.is_dir() and '_traces_' in dir.name:
            v4n, v6n, v4a, v6a = get_path_node_stats(dir, return_sets=True)
            v4nodes.update(v4n)
            v6nodes.update(v6n)
            v4active.update(v4a)
            v6active.update(v6a)

    if return_sets:
        return (v4nodes, v6nodes, v4active, v6active)
    else:
        return (len(v4nodes), len(v6nodes), len(v4active), len(v6active))

# do this with zip_longest
# def write_latex_table(basedirs):
#   linemap = {} # { port: [ values ]}
#   print('\makecell[lc]{{\\texttt{{{0}}}}}'.format(p))
