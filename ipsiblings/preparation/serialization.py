# libts/serialization.py
#
# (c) 2018 Marco Starke
#


import csv
import os
from typing import Tuple, List, Union, Iterable

from .. import liblog, libtools
from ..model import PreparedTargets

log = liblog.get_root_logger()


class TargetSerialization:
    PRIMARY_DELIMITER = '\t'
    SECONDARY_DELIMITER = ','
    TERTIARY_DELIMITER = ':'
    NONE_MARKER = '--None--'

    @classmethod
    def export_targets(cls, prepared_targets: PreparedTargets, directory: str):
        os.makedirs(directory, exist_ok=True)
        with open(cls.get_targets_path(directory), 'w', newline='', encoding='utf-8') as targets_file:
            writer = csv.writer(targets_file, delimiter=cls.PRIMARY_DELIMITER)
            for target in prepared_targets:
                writer.writerow(list(target.key) + [
                    ",".join(target.domains),
                    cls.tcp_options_to_str(target.tcp_options) if target.tcp_options else cls.NONE_MARKER
                ] + [value for tup in target.timestamps.timestamps for value in tup])

    @classmethod
    def get_timestamps_path(cls, directory):
        return os.path.join(directory, 'timestamps.tsv')

    @classmethod
    def get_targets_path(cls, directory):
        return os.path.join(directory, 'targets.tsv')

    @classmethod
    def tcp_options_to_str(cls, tcp_options: List[Tuple[str, Union[Iterable, str]]]) -> str:
        results = []
        for name, option_value in tcp_options:
            if libtools.is_iterable(option_value):
                fields = [name] + [str(item) for item in option_value]
            else:
                fields = [name, str(option_value)]
            results.append(cls.TERTIARY_DELIMITER.join(fields))
        return cls.SECONDARY_DELIMITER.join(results)

    @classmethod
    def tcp_options_from_str(cls, data: str) -> Union[List[Tuple[str, Union[Iterable, str]]], None]:
        if data == cls.NONE_MARKER:
            return None
        options_data = data.split(sep=cls.SECONDARY_DELIMITER)
        result = []
        for option_data in options_data:
            fields = option_data.split(sep=cls.TERTIARY_DELIMITER)
            option_name, *option_values = fields
            if len(option_values) == 1:
                option_values = option_values[0]  # for some reason, a single value is represented without a list
            result.append((option_name, option_values))
        return result
