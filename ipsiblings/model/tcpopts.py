from typing import List, Tuple, Union, Iterable

from ipsiblings import libtools
from ipsiblings.model import const


class TcpOptions:
    def __init__(self, data_raw: List[Tuple[str, Union[Iterable, str]]]):
        self.data = data_raw

    def __iter__(self):
        yield from self.data

    def __len__(self):
        return len(self.data)

    @classmethod
    def from_str(cls, inp: str):
        if inp == const.NONE_MARKER:
            return None
        options_data = inp.split(sep=const.SECONDARY_DELIMITER)
        result = []
        for option_data in options_data:
            fields = option_data.split(sep=const.TERTIARY_DELIMITER)
            option_name, *option_values = fields
            if len(option_values) == 1:
                option_values = option_values[0]  # for some reason, a single value is represented without a list
            result.append((option_name, option_values))
        return cls(result)

    def __str__(self):
        results = []
        for name, option_value in self:
            if libtools.is_iterable(option_value):
                fields = [str(name)] + [str(item) for item in option_value]
            else:
                fields = [str(name), str(option_value)]
            results.append(const.TERTIARY_DELIMITER.join(fields))
        return const.SECONDARY_DELIMITER.join(results)
