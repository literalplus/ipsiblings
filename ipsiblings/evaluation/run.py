import abc
import pathlib
from typing import List, Iterator, Optional

from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from . import plot, export
from .evaluator.all import evaluate_with_all
from .model.targetpropertycache import TargetPropertyCache
from .stats.export import StatsExporter, CandidateDecisionImporter
from .stats.model import Stats
from .. import config, logsetup
from ..model import SiblingCandidate

log = logsetup.get_root_logger()


class AbstractProcessor(metaclass=abc.ABCMeta):
    """
    Abstract base class for evaluation processor logic.
    """

    def __init__(self, conf: config.AppConfig):
        self.conf = conf
        self.total_stats: Optional[Stats] = Stats() if conf.eval.totals_in_memory else None

    def run(self, batch_id: int, candidate_iter: Iterator[SiblingCandidate]):
        evaluated = [EvaluatedSibling(c) for c in candidate_iter]
        if not len(evaluated):
            return  # happens if (#targets % batch_size) == 0
        batch_dir = pathlib.Path(self.conf.base_dir) / f'batch_{batch_id:06}'
        batch_dir.mkdir(parents=True, exist_ok=True)
        batch_stats = Stats(self.total_stats)
        self._handle_batch(evaluated, batch_stats, batch_dir)
        StatsExporter(batch_dir).export_all(batch_stats)

    @abc.abstractmethod
    def _handle_batch(self, evaluated: List[EvaluatedSibling], batch_stats: Stats, batch_dir: pathlib.Path):
        pass

    def export_total_stats(self):
        if self.total_stats is not None:
            StatsExporter(pathlib.Path(self.conf.base_dir)).export_all(self.total_stats)


class StatsReaderProcessor(AbstractProcessor):
    """
    An evaluation processor that solely recalculates statistics but does not run actual evaluation.
    """

    def __init__(self, conf: config.AppConfig):
        super(StatsReaderProcessor, self).__init__(conf)
        log.info('Evaluation: Recalculating stats only.')
        self.importer = CandidateDecisionImporter()

    def _handle_batch(self, evaluated: List[EvaluatedSibling], batch_stats: Stats, batch_dir: pathlib.Path):
        self.importer.import_all(batch_stats, batch_dir)


class EvaluationProcessor(AbstractProcessor):
    """
    The default evaluation processor that runs actual evaluation and maintains a property cache.
    """

    def _handle_batch(self, evaluated: List[EvaluatedSibling], batch_stats: Stats, batch_dir: pathlib.Path):
        evaluate_with_all(evaluated, batch_stats, batch_dir, self.conf)
        if not self.conf.eval.discard_results:
            if self.conf.paths.candidates_out:
                self._do_export(evaluated, batch_dir / self.conf.paths.candidates_out)
            if self.conf.eval.export_plots:
                plot.plot_all(evaluated, batch_dir / 'plots.pdf')
            TargetPropertyCache.clear()

    def _do_export(self, evaluated: List[EvaluatedSibling], out_file: pathlib.Path):
        export.write_results(evaluated, out_file)
        log.info(f'Wrote {len(evaluated)} result records to {out_file}.')


def provide_processor(conf: config.AppConfig) -> AbstractProcessor:
    """
    Decides on the processor based on configuration options.
    """

    if conf.eval.recalc_stats:
        return StatsReaderProcessor(conf)
    else:
        return EvaluationProcessor(conf)
