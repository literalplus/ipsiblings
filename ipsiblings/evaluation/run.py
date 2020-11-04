import pathlib
from typing import List, Iterator, Optional

from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from . import plot, export
from .evaluator.all import evaluate_with_all
from .model.targetpropertycache import TargetPropertyCache
from .stats.export import StatsExporter
from .stats.model import Stats
from .. import config, logsetup
from ..model import SiblingCandidate

log = logsetup.get_root_logger()


class EvaluationProcessor:
    def __init__(self, conf: config.AppConfig):
        self.conf = conf
        self.total_stats: Optional[Stats] = Stats() if conf.eval.totals_in_memory else None

    def run(self, batch_id: int, candidate_iter: Iterator[SiblingCandidate]):
        evaluated = [EvaluatedSibling(c) for c in candidate_iter]
        if not len(evaluated):
            return  # happens if (#targets % batch_size) == 0
        batch_dir = pathlib.Path(self.conf.base_dir) / f'batch_{batch_id:06}'
        batch_dir.mkdir(parents=True, exist_ok=True)
        batch_stats = Stats()
        evaluate_with_all(evaluated, self.total_stats, batch_stats, batch_dir, self.conf)
        if not self.conf.eval.discard_results:
            if self.conf.paths.candidates_out:
                self._do_export(evaluated, batch_dir / self.conf.paths.candidates_out)
            StatsExporter(batch_dir).export_all(batch_stats)
            if self.conf.eval.export_plots:
                plot.plot_all(evaluated, batch_dir / 'plots.pdf')
            TargetPropertyCache.clear()

    def export_total_stats(self):
        if self.total_stats is not None:
            StatsExporter(pathlib.Path(self.conf.base_dir)).export_all(self.total_stats)

    def _do_export(self, evaluated: List[EvaluatedSibling], out_file: pathlib.Path):
        export.write_results(evaluated, out_file)
        log.info(f'Wrote {len(evaluated)} result records to {out_file}.')
