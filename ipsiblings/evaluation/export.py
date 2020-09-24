# libsiblings/export.py
#
# (c) 2018 Marco Starke
#
# Most code in this file is based on or taken from the work of Scheitle et al. 2017:
# "Large scale Classification of IPv6-IPv4 Siblings with Variable Clock Skew"
# -> https://github.com/tumi8/siblings (GPLv2)
#

import csv
from typing import List, Dict

from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling


def write_results(evaluated_siblings: List[EvaluatedSibling], out_path):
    """
    Write available results to resultfile
    """
    # TODO: LRT keys: 'ip4', 'ip6', 'port4', 'port6', 'domains', 'hz4', 'hz6', 'hz4_R2', 'hz6_R2', 'raw_ts_diff',
    #             'ip4_tcpopts', 'ip6_tcpopts', 'ssh_keys_match', 'ssh_agents_match', 'geo4', 'geo6', 'geoloc_diff',
    #             'status', 'is_sibling'
    # TODO: Missing handling for SSH key/agent match

    all_keys = set()
    candidate_exports: List[Dict[str, str]] = []
    for evaluated_sibling in evaluated_siblings:
        export = evaluated_sibling.export()
        all_keys.update(export.keys())
        candidate_exports.append(export)
    with open(out_path, mode='w', newline='', encoding='utf-8') as csv_file:
        keys_sorted = list(all_keys)
        keys_sorted.sort()
        writer = csv.DictWriter(csv_file, fieldnames=keys_sorted, dialect=csv.excel_tab)
        writer.writeheader()
        writer.writerows(candidate_exports)
