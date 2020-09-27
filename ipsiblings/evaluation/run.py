import pathlib
from typing import List, Iterator

from . import plot, export
from .evaluatedsibling import EvaluatedSibling
from .evaluator.all import evaluate_with_all
from .. import config, liblog
from ..model import SiblingCandidate

log = liblog.get_root_logger()


class EvaluationProcessor:
    def __init__(self, conf: config.AppConfig):
        self.conf = conf

    def run(self, batch_id: int, candidate_iter: Iterator[SiblingCandidate]):
        batch_dir = pathlib.Path(self.conf.base_dir) / f'batch_{batch_id:06}'
        evaluated = [EvaluatedSibling(c) for c in candidate_iter]
        evaluate_with_all(evaluated, batch_dir, self.conf)
        if self.conf.paths.candidates_out:
            self._do_export(evaluated, batch_dir / self.conf.paths.candidates_out)
        if self.conf.eval.export_plots:
            plot.plot_all(evaluated, batch_dir / 'plots.pdf')

    def _do_export(self, evaluated: List[EvaluatedSibling], out_file: pathlib.Path):
        export.write_results(evaluated, out_file)
        log.info(f'Wrote {len(evaluated)} result records to {out_file}.')
