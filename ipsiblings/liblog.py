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

from . import libconstants as const

NOTSET = logging.NOTSET
DEBUG = logging.DEBUG
INFO = logging.INFO
WARNING = logging.WARNING
ERROR = logging.ERROR
CRITICAL = logging.CRITICAL


def setup_root_logger(format=const.LOG_FORMAT):
    root = logging.getLogger()

    handler = logging.StreamHandler(sys.stdout)
    handler.flush = sys.stdout.flush
    formatter = logging.Formatter(format)
    handler.setFormatter(formatter)

    root.addHandler(handler)

    return root


def get_root_logger():
    return logging.getLogger()


def setup_custom_logger(name, loglevel=NOTSET, format='%(asctime)s - %(module)s - %(levelname)s: %(message)s'):
    formatter = logging.Formatter(fmt=format)

    handler = logging.StreamHandler()
    handler.flush = sys.stdout.flush
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(loglevel)
    logger.addHandler(handler)

    return logger


def get_custom_logger(name):
    return logging.getLogger(name)


def set_scapy_loglevel(lvl):
    logging.getLogger('scapy.runtime').setLevel(lvl)
