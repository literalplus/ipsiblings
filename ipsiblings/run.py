#!/usr/bin/env python3
#
# main.py
#
# (c) 2018 Marco Starke
#

"""
Does the dirty preparation work so that the bootstrap module can act just upon business objects.
"""

import csv
import sys

from . import libconstants, config, bootstrap
from . import logsetup
from .config.util import print_usage_and_exit
from .model import JustExit, BusinessException

# setup root logger
log = logsetup.setup_root_logger()
# set log level for scapy => disables warnings
logsetup.set_scapy_loglevel(40)
# set field_size_limit() from 131072 (2**17) to 262144 (2**18)
csv.field_size_limit(262144)


def _validate_config(conf):
    if conf.end_index is not None:
        if conf.start_index < 0 or conf.end_index < 1:
            print_usage_and_exit('--from/--to can not be negative/zero')
        if conf.start_index >= conf.end_index:
            print_usage_and_exit('--to can not be less or equal to --from')


def _prepare_context():
    conf = config.AppConfig()
    _validate_config(conf)
    log.setLevel(conf.log_level)
    wiring = bootstrap.Wiring(conf)
    bootstrap.bridge_wiring_to_legacy(wiring, libconstants)
    return conf, wiring


def _run_main():
    conf, wiring = _prepare_context()
    wiring.os_tuning.apply()
    try:
        if conf.flags.only_init:
            log.warning('Exiting after initialisation as requested.')
            raise JustExit
        bootstrap.run(wiring)
    finally:
        wiring.os_tuning.try_revert()


def main():
    # noinspection PyBroadException
    try:
        _run_main()
    except BusinessException:
        log.exception("An error occurred during execution")
        sys.exit(-3)
    except JustExit:
        pass
    except Exception:
        log.exception("Unexpected exception encountered")
        sys.exit(-4)


if __name__ == '__main__':
    main()
