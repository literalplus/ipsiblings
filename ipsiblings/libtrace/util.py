# libtrace/util.py
#
# (c) 2018 Marco Starke
#

import hashlib


def get_ts_tcp_seq(trace_set_id_list):
    h = hashlib.md5()
    for ts_id in trace_set_id_list:
        h.update(ts_id.encode('utf-8'))
    return int(h.hexdigest()[:8], 16)


def get_tcp_seq(trace_set_id):
    return int(trace_set_id[:8], 16)


def get_all_active_nodes(trace_set_list):
    """
    -> ( { ip4: { portlist } }, { ip6: { portlist } }, { ip4: { trace_set_id } }, { ip6: { trace_set_id } } )

    To assign the timestamp results to all trace sets containing the same IP, the 3rd and 4th return value can be used.
    """
    v4nodes = {}  # all ip4 mapping to ports available
    v6nodes = {}  # all ip6 mapping to ports available
    v4tracesetmap = {}
    v6tracesetmap = {}

    for trace_set_id, trace_set in trace_set_list.items():
        for trace in trace_set.get_traces().values():
            for ip, portlist in trace.get_active_nodes()[0].items():
                if ip in v4nodes:
                    v4nodes[ip].update(portlist)
                else:
                    v4nodes[ip] = set(portlist)

                if ip in v4tracesetmap:
                    v4tracesetmap[ip].update([trace_set_id])
                else:
                    v4tracesetmap[ip] = {trace_set_id}

            for ip, portlist in trace.get_active_nodes()[1].items():
                if ip in v6nodes:
                    v6nodes[ip].update(portlist)
                else:
                    v6nodes[ip] = set(portlist)

                if ip in v6tracesetmap:
                    v6tracesetmap[ip].update([trace_set_id])
                else:
                    v6tracesetmap[ip] = {trace_set_id}

    return v4nodes, v6nodes, v4tracesetmap, v6tracesetmap


def total_number_active_nodes(trace_set_dict):
    nr_nodes4 = 0
    nr_nodes6 = 0
    for trace_set in trace_set_dict.values():
        nr4, nr6 = trace_set.get_number_of_active_nodes()
        nr_nodes4 = nr_nodes4 + nr4
        nr_nodes6 = nr_nodes6 + nr6

    return nr_nodes4, nr_nodes6
