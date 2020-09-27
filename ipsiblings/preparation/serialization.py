# libts/serialization.py
#
# (c) 2018 Marco Starke
#


import csv
import os

from .. import liblog
from ..model import PreparedTargets, const

log = liblog.get_root_logger()


class TargetSerialization:
    @classmethod
    def export_targets(cls, prepared_targets: PreparedTargets, directory: str):
        os.makedirs(directory, exist_ok=True)
        with open(cls.get_targets_path(directory), 'w', newline='', encoding='utf-8') as targets_file:
            i = 0
            writer = csv.writer(targets_file, delimiter=const.PRIMARY_DELIMITER)
            for target in prepared_targets:
                writer.writerow(list(target.key) + [
                    ",".join(target.domains) if target.domains else const.NONE_MARKER,
                    str(target.tcp_options) if target.tcp_options else const.NONE_MARKER
                ] + [value for tup in target.timestamps.timestamps for value in tup])
                i += 1
                if (i % 100) == 0:
                    targets_file.flush()

    @classmethod
    def get_timestamps_path(cls, directory):
        return os.path.join(directory, 'timestamps.tsv')

    @classmethod
    def get_targets_path(cls, directory):
        return os.path.join(directory, 'targets.tsv')
