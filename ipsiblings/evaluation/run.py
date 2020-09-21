import pathlib
from typing import Dict, Tuple

from . import plot, keyscan, export
from .. import libconstants, config, liblog
from ..model import JustExit, SiblingCandidate

log = liblog.get_root_logger()


def _handle_ssh_keyscan(candidates: Dict[Tuple, SiblingCandidate], conf):
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


def run(candidates: Dict[Tuple, SiblingCandidate], conf: config.AppConfig):
    _handle_ssh_keyscan(candidates, conf)
    log.info('Calculations for evaluation started ...')
    for c in candidates.values():
        try:
            c.evaluate()
        except Exception:
            log.exception('Exception during evaluation')
    log.info('Finished sibling candidate calculations')
    ##### OUTFILE #####
    if conf.paths.candidates_out:
        resultfile = pathlib.Path(conf.paths.candidates_out)
        if not resultfile.is_absolute():
            resultfile = conf.base_dir / resultfile
        log.info(f'Writing generated candidates to {resultfile}...')
        nr_records = export.write_results(
            candidates.values(), resultfile, low_runtime=conf.candidates.low_runtime
        )
        log.info(f'Wrote {nr_records} result records.')
    ##### PLOT #####
    if conf.flags.export_plots:  # plots all candidates to base_directory/const.PLOT_FILE_NAME
        log.info('Starting plot process ...')
        plot.plot_all(candidates.values(), libconstants.PLOT_FILE_NAME)
        log.info('Finished printing charts')
