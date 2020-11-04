import contextlib
import csv
import pathlib

from ipsiblings.evaluation.model import SiblingStatus
from ipsiblings.evaluation.stats.model import Stats, CrossStats

FIL_SIBLINGS = 'siblings.tsv'
FIL_MULTI_SIBLINGS = 'multi-siblings.tsv'
FIL_STATUSES = 'classifications.sum.tsv'
FIL_CROSS_STATS = 'cross-stats.sum.tsv'

COL_SIBLINGS_4 = 'ip4'
COL_SIBLINGS_6 = 'ip6'
COLS_SIBLINGS = [COL_SIBLINGS_4, COL_SIBLINGS_6]

COL_STATUS_KEY = 'evaluator'
COLS_STATUSES = [COL_STATUS_KEY] + [c.name for c in SiblingStatus]

COL_CS_KEY = 'algorithm'
COLPFX_CS_POSITIVE = 'pos_'
COLPFX_CS_NEGATIVE = 'neg_'
COLIFX_CS_TRUE_STATUS = 'was_'
COLSFX_CS_PROBABLE = 'probable'
COLSFX_CS_IMPROBABLE = 'improbable'
COLS_CS_POSNEG = [f'{COLIFX_CS_TRUE_STATUS}{status}' for status in SiblingStatus] + \
                 [COLSFX_CS_PROBABLE, COLSFX_CS_IMPROBABLE]
COL_CS_CONFLICT = 'conflict'
COL_CS_INDECISIVE = 'indecisive'
COL_CS_ERROR = 'error'
COLS_CS = [COL_CS_KEY] + \
          [f'{COLPFX_CS_POSITIVE}{col}' for col in COLS_CS_POSNEG] + \
          [f'{COLPFX_CS_NEGATIVE}{col}' for col in COLS_CS_POSNEG] + \
          [COL_CS_CONFLICT, COL_CS_INDECISIVE, COL_CS_ERROR]


class StatsImporter:
    def __init__(self, infile: pathlib.Path):
        self.infile = infile

    # TODO


class StatsExporter:
    def __init__(self, outdir: pathlib.Path):
        self.outdir = outdir

    def export_all(self, stats: Stats):
        self.export_siblings(stats)
        self.export_classifications(stats)
        self.export_cross(stats.cross_stats)

    def export_siblings(self, stats: Stats):
        with self._open_fil(FIL_MULTI_SIBLINGS, append=True) as (existed_before, fil):
            writer = csv.writer(fil, dialect=csv.excel_tab)
            if not existed_before:
                writer.writerow(('ip',))
            for ip in stats.multi_siblings:
                writer.writerow((ip,))
        with self._open_fil(FIL_SIBLINGS, append=True) as (existed_before, fil):
            writer = csv.writer(fil, dialect=csv.excel_tab)
            if not existed_before:
                writer.writerow(COLS_SIBLINGS)
            for ip4, ip6 in stats.sibling_pairs:
                writer.writerow((ip4, ip6))

    @contextlib.contextmanager
    def _open_fil(self, name: str, append: bool = False):
        path = self.outdir / name
        exited_before = path.exists()
        with open(path, 'a' if append else 'w', encoding='utf-8', newline='') as fil:
            if append:
                yield exited_before, fil
            else:
                yield fil

    def export_classifications(self, stats: Stats):
        with self._open_fil(FIL_STATUSES, append=False) as fil:
            writer = csv.DictWriter(fil, COLS_STATUSES, dialect=csv.excel_tab)
            writer.writeheader()
            for provider, status_counts in stats.provider_status_counts.items():
                res = {s.name: str(c) for s, c in status_counts.items()}
                res[COL_STATUS_KEY] = str(provider)
                writer.writerow(res)

    def export_cross(self, cross_stats: CrossStats):
        with self._open_fil(FIL_CROSS_STATS, append=False) as fil:
            writer = csv.DictWriter(fil, COLS_CS, dialect=csv.excel_tab)
            writer.writeheader()
            for algorithm, metrics in cross_stats.metrics.items():
                res = {
                    COL_CS_KEY: algorithm,
                    COL_CS_CONFLICT: str(metrics.conflicts),
                    COL_CS_INDECISIVE: str(metrics.indecisives),
                    COL_CS_ERROR: str(metrics.errors),
                }
                for is_positive, sub_metrics in metrics.posneg.items():
                    prefix = COLPFX_CS_POSITIVE if is_positive else COLPFX_CS_NEGATIVE
                    for true_result, count in sub_metrics.true_values.items():
                        res[f'{prefix}{COLIFX_CS_TRUE_STATUS}{true_result.name}'] = str(count)
                    res[f'{prefix}{COLSFX_CS_PROBABLE}'] = str(sub_metrics.probables)
                    res[f'{prefix}{COLSFX_CS_IMPROBABLE}'] = str(sub_metrics.improbables)
