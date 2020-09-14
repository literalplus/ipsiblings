import csv
from typing import Dict, Tuple

from ipsiblings import config, liblog
from ipsiblings.preparation.serialization import TargetSerialization
from ipsiblings.preparation.target import Target

log = liblog.get_root_logger()


class FilesystemProvider:
    def __init__(self):
        self.base_dir = None

    def configure(self, conf: config.AppConfig):
        self.base_dir = conf.base_dir

    def provide(self) -> Dict[str, Target]:
        targets: Dict[Tuple, Target] = {}
        with open(
                TargetSerialization.get_targets_path(self.base_dir), 'r', newline='', encoding='utf-8'
        ) as targets_file:
            reader = csv.reader(targets_file, delimiter=TargetSerialization.PRIMARY_DELIMITER)
            for record in reader:
                key, rest = Target.key_and_rest_from(record)
                target = Target(key)
                domains_data, tcp_options_str, *ts_data = rest
                for domain in domains_data.split(TargetSerialization.SECONDARY_DELIMITER):
                    target.add_domain(domain)
                target.tcp_options = TargetSerialization.tcp_options_from_str(tcp_options_str)
                for even_idx in range(0, len(ts_data) - 1, 2):  # subtract 1 to skip lonely odd indices at the end
                    remote_ts = int(ts_data[even_idx])
                    local_ts = float(ts_data[even_idx + 1])
                    target.handle_timestamp(remote_ts, local_ts, None)
                targets[key] = target
        return {address: target for ((_, address, _), target) in targets}
