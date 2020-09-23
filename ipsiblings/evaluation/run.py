import pathlib
from typing import Dict, Tuple, List

from . import plot, keyscan, export
from .evaluatedsibling import EvaluatedSibling
from .evaluator.all import evaluate_with_all
from .. import libconstants, config, liblog
from ..model import JustExit, SiblingCandidate

log = liblog.get_root_logger()


def _handle_ssh_keyscan(candidates: Dict[Tuple, SiblingCandidate], conf):
    if not conf.candidates.skip_keyscan:
        log.info('Preparing ssh-keyscan ...')
        # TODO: migrate keyscan to new model
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


def _do_export(evaluated: List[EvaluatedSibling], conf):
    out_file = pathlib.Path(conf.paths.candidates_out)
    if not out_file.is_absolute():
        out_file = conf.base_dir / out_file
    log.info(f'Writing evaluated candidates to {out_file}...')
    export.write_results(evaluated, out_file)
    log.info(f'Wrote {len(evaluated)} result records.')


def run(candidates: Dict[Tuple, SiblingCandidate], conf: config.AppConfig):
    evaluated = [EvaluatedSibling(c) for c in candidates.values()]
    _handle_ssh_keyscan(candidates, conf)
    log.info('Calculations for evaluation started ...')
    for evaluated_sibling in evaluated:
        evaluate_with_all(evaluated_sibling)
    log.info('Finished sibling candidate calculations')
    if conf.paths.candidates_out:
        _do_export(evaluated, conf)
    if conf.flags.export_plots:
        log.info('Starting plot process ...')
        plot.plot_all(evaluated, conf.base_dir / 'plots.pdf')
        log.info('Finished printing charts')
