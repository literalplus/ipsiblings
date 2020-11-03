import pathlib
from typing import List, Iterator

from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from . import plot, export
from .evaluator.all import evaluate_with_all
from .model.targetpropertycache import TargetPropertyCache
from .. import config, logsetup
from ..model import SiblingCandidate

log = logsetup.get_root_logger()


class EvaluationProcessor:
    def __init__(self, conf: config.AppConfig):
        self.conf = conf

    def run(self, batch_id: int, candidate_iter: Iterator[SiblingCandidate]):
        evaluated = [EvaluatedSibling(c) for c in candidate_iter]
        if not len(evaluated):
            return  # happens if (#targets % batch_size) == 0
        batch_dir = pathlib.Path(self.conf.base_dir) / f'batch_{batch_id:06}'
        batch_dir.mkdir(parents=True, exist_ok=True)
        evaluate_with_all(evaluated, batch_dir, self.conf)
        if self.conf.paths.candidates_out and not self.conf.eval.discard_results:
            self._do_export(evaluated, batch_dir / self.conf.paths.candidates_out)
        if self.conf.eval.export_plots and not self.conf.eval.discard_results:
            plot.plot_all(evaluated, batch_dir / 'plots.pdf')
        TargetPropertyCache.clear()

    def _do_export(self, evaluated: List[EvaluatedSibling], out_file: pathlib.Path):
        export.write_results(evaluated, out_file)
        log.info(f'Wrote {len(evaluated)} result records to {out_file}.')
