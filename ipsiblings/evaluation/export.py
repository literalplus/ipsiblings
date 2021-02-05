import csv
import pathlib
from typing import List

from ipsiblings.evaluation.model.exportregistry import ExportRegistry
from ipsiblings.evaluation.model.sibling import EvaluatedSibling


def write_results(evaluated_siblings: List[EvaluatedSibling], out_path: pathlib.Path):
    """
    Writes the batch results represented by the parameters to a standard-format file.
    """

    # LRT keys: 'ip4', 'ip6', 'port4', 'port6', 'domains', 'hz4', 'hz6', 'hz4_R2', 'hz6_R2', 'raw_ts_diff',
    #             'ip4_tcpopts', 'ip6_tcpopts', 'ssh_keys_match', 'ssh_agents_match', 'geo4', 'geo6', 'geoloc_diff',
    #             'status', 'is_sibling'
    existed_before = out_path.is_file()
    with open(out_path, mode='a', newline='', encoding='utf-8') as csv_file:
        keys_sorted = ExportRegistry.get_header_fields()
        writer = csv.DictWriter(csv_file, fieldnames=keys_sorted, dialect=csv.excel_tab)
        if not existed_before:
            writer.writeheader()
        for evaluated_sibling in evaluated_siblings:
            export = evaluated_sibling.export()
            writer.writerow(export)
