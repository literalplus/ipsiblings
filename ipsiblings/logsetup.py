# liblog.py
#
# (c) 2018 Marco Starke
#


"""
Module liblog

This is a wrapper for logging setup.

For details see: https://stackoverflow.com/a/7622029
"""

import logging
import sys

NOTSET = logging.NOTSET
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL


def setup_root_logger():
    root = logging.getLogger()

    handler = logging.StreamHandler(sys.stdout)
    handler.flush = sys.stdout.flush
    formatter = logging.Formatter('%(asctime)s - %(module)s - %(funcName)s - %(levelname)s: %(message)s')
    handler.setFormatter(formatter)

    root.addHandler(handler)

    return root


def get_root_logger():
    return logging.getLogger()


def set_scapy_loglevel(lvl):
    logging.getLogger('scapy.runtime').setLevel(lvl)
