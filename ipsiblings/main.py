#!/usr/bin/env python3
#
# main.py
#
# (c) 2018 Marco Starke
#

"""
Module main

This is the main module.

"""

import csv
import os
import pathlib
import sys
import traceback

from . import config, bootstrap, libconstants
from . import keyscan
from . import liblog
from . import libsiblings
from . import settings
from .bootstrap.exception import JustExit, BusinessException

# setup root logger
log = liblog.setup_root_logger()
# set log level for scapy => disables warnings
liblog.set_scapy_loglevel(libconstants.LOG_LVL_SCAPY)
# set field_size_limit() from 131072 (2**17) to 262144 (2**18)
csv.field_size_limit(262144)


def _validate_config(conf):
    if conf.targetprovider.resolved_ips_path and not conf.targetprovider.has_resolved:
        config.print_usage_and_exit('-f/--resolved-file can only be used with -s/--resolved')

    if conf.targetprovider.do_download and not conf.targetprovider.has_resolved:
        config.print_usage_and_exit('-o/--download-alexa can only be used with -s/--resolved')

    if conf.end_index is not None:
        if conf.start_index < 0 or conf.end_index < 1:
            config.print_usage_and_exit('--from/--to can not be negative/zero')
        if conf.start_index >= conf.end_index:
            config.print_usage_and_exit('--to can not be less or equal to --from')


def _bridge_config_to_legacy(conf: config.AppConfig, const: libconstants):
    log.setLevel(conf.log_level)
    const.BASE_DIRECTORY = conf.base_dir


def handle_post_tasks(candidates, conf):
    handle_ssh_keyscan(candidates, conf)
    log.info('Calculations for evaluation started ...')
    for c in candidates.values():
        try:
            c.evaluate()
        except Exception:
            log.exception('Exception during evaluation')
    log.info('Finished sibling candidate calculations')
    ##### OUTFILE #####
    if conf.candidates.out_csv:
        resultfile = pathlib.Path(conf.candidates.out_csv)
        if not resultfile.is_absolute():
            resultfile = libconstants.BASE_DIRECTORY / resultfile
        log.info('Writing resultfile [{0}] ...'.format(resultfile))
        nr_records = libsiblings.write_results(candidates.values(), resultfile,
                                               low_runtime=conf.candidates.low_runtime)
        log.info('Wrote {0} result records to file'.format(nr_records))
    ##### PLOT #####
    if conf.flags.do_print:  # plots all candidates to base_directory/const.PLOT_FILE_NAME
        log.info('Starting plot process ...')
        libsiblings.plot_all(candidates.values(), libconstants.PLOT_FILE_NAME)
        log.info('Finished printing charts')
    if not conf.candidates.out_csv and not conf.flags.do_print:
        log.info('Nothing more to do ... Exiting ...')


def handle_ssh_keyscan(candidates, conf):
    if not conf.candidates.skip_keyscan:
        log.info('Preparing ssh-keyscan ...')
        sshkeyscan = keyscan.Keyscan(
            candidates,
            directory=conf.base_dir, timeout=None,
            key_file_name=libconstants.SSH_KEYS_FILENAME,
            agent_file_name=libconstants.SSH_AGENTS_FILENAME,
            keyscan_command=libconstants.SSH_KEYSCAN_COMMAND
        )
        if not sshkeyscan.has_keys():  # assign available keys to candidates
            log.info('No keyfile found, starting ssh-keyscan processes')
            done = sshkeyscan.run(write_keyfile=True, split_output=False)  # if not available, run ssh-keyscan
            if not done:
                log.warning('No nodes to scan for SSH keys ...')
            else:
                log.info('Finished ssh-keyscan')
        else:
            keys_path = pathlib.Path(conf.base_dir, libconstants.SSH_KEYS_FILENAME)
            log.info(f'Loaded ssh keys from file [{keys_path}]')
    else:
        log.info('No ssh-keyscan requested')
    # stop here if solely ssh-keyscan was requested
    if conf.candidates.only_keyscan:
        log.info('--only-ssh-keyscan requested, exiting now ...')
        raise JustExit


def main():
    conf = config.AppConfig()
    _validate_config(conf)
    _bridge_config_to_legacy(conf, libconstants)
    wiring = bootstrap.Wiring(conf)
    bootstrap.bridge_wiring_to_legacy(wiring, libconstants)

    # debug run requested, exiting now
    if conf.debug:
        log.warning('DEBUG run -> exiting now ...')
        raise JustExit

    log.info('Started')
    candidates = bootstrap.run(wiring)
    handle_post_tasks(candidates, conf)

    return 0


################################################################################
################################################################################
################################################################################

if __name__ == '__main__':
    if settings.dependency_error():
        sys.exit(-1)  # do not continue ...

    if libconstants.OPTIMIZE_OS_SETTINGS or libconstants.DISABLE_TIME_SYNC_SERVICE or libconstants.FIREWALL_APPLY_RULES:
        os_settings = settings.Settings(backup_to_file=libconstants.WRITE_OS_SETTINGS_TO_FILE)

    ret = -42
    error = False

    try:
        if libconstants.OPTIMIZE_OS_SETTINGS:
            os_settings.optimize_system_config()
        if libconstants.DISABLE_TIME_SYNC_SERVICE:
            os_settings.disable_timesync()
        if libconstants.FIREWALL_APPLY_RULES:
            os_settings.enable_firewall_rules()

        ret = main()  # start main execution

    except BusinessException:
        log.exception()
        ret = -3
    except JustExit:
        ret = 0
    except Exception as e:
        error = True
        exc_type, exc_object, exc_traceback = sys.exc_info()
        ef = traceback.extract_tb(exc_traceback)[-1]  # get the inner most error frame
        string = '{0} in {1} (function: \'{2}\') at line {3}: "{4}" <{5}>'.format(exc_type.__name__,
                                                                                  os.path.basename(ef.filename),
                                                                                  ef.name, ef.lineno, str(e), ef.line)
        log.critical(string)
        print('CRITICAL: {0}'.format(string), file=sys.stderr)  # additionally print to stderr
    except (KeyboardInterrupt, SystemExit):
        error = True
        raise
    finally:
        # remove any applied firewall rules
        if libconstants.FIREWALL_APPLY_RULES:
            os_settings.disable_firewall_rules()
        # restart time sync service if it was stopped previously
        if libconstants.DISABLE_TIME_SYNC_SERVICE:
            os_settings.enable_timesync()
        # in any other case restore default settings
        if libconstants.OPTIMIZE_OS_SETTINGS:
            os_settings.restore_system_config()

    sys.exit(ret)
