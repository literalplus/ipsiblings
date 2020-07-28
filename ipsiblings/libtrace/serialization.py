# libtrace/serialization.py
#
# (c) 2018 Marco Starke
#

import os

from .traceset import TraceSet
from .. import liblog

log = liblog.get_root_logger()


def write_trace_sets(base_dir, trace_set_dict):
    """
    Returns number of written trace sets

    base_dir          absolute directory path to write trace sets
    trace_set_dict    { traceset_id: trace_set }
    """
    counter = 0
    for ts_id, traceset in trace_set_dict.items():
        traceset.to_file(base_dir)
        counter = counter + 1
    return counter


def load_trace_sets(base_dir, silent_dir='', v4bl_re=None, v6bl_re=None, iface=None):
    """
    Loads all trace sets from base_dir, ignores silent_dir in base_dir.
    Use blacklist regex and interface to pass through to the Trace objects.
    Returns { trace_set_id: trace_set }
    """
    ts_dirs = [os.path.join(base_dir, name) for name in os.listdir(base_dir) if
               os.path.isdir(os.path.join(base_dir, name)) and name not in silent_dir]

    trace_set_dict = {}

    for ts_dir in ts_dirs:
        tset = TraceSet()
        tset.from_file(ts_dir, v4bl_re=v4bl_re, v6bl_re=v6bl_re, iface=iface)
        id = tset.id()
        if id not in trace_set_dict:
            trace_set_dict[id] = tset
        else:
            log.error('TraceSet ID {0} already in dictionary!'.format(tset.id()))

    return trace_set_dict
