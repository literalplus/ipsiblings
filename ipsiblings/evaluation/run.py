import pathlib
from typing import Dict, Tuple, List

from . import plot, export
from .evaluatedsibling import EvaluatedSibling
from .evaluator.all import evaluate_with_all
from .. import config, liblog
from ..model import SiblingCandidate

log = liblog.get_root_logger()


def _do_export(evaluated: List[EvaluatedSibling], conf):
    out_file = pathlib.Path(conf.paths.candidates_out)
    if not out_file.is_absolute():
        out_file = pathlib.Path(conf.base_dir) / out_file
    log.info(f'Writing evaluated candidates to {out_file}...')
    export.write_results(evaluated, out_file)
    log.info(f'Wrote {len(evaluated)} result records.')


def run(candidates: Dict[Tuple, SiblingCandidate], conf: config.AppConfig):
    evaluated = [EvaluatedSibling(c) for c in candidates.values()]
    log.info('Now evaluating...')
    evaluate_with_all(evaluated, conf)
    log.info('Evaluation finished.')
    if conf.paths.candidates_out:
        _do_export(evaluated, conf)
    if conf.eval.export_plots:
        log.info('Starting plot process ...')
        plot.plot_all(evaluated, pathlib.Path(conf.base_dir) / 'plots.pdf')
        log.info('Finished printing charts')
