import csv
from typing import Dict, Tuple

from ipsiblings import config, liblog
from ipsiblings.model import Target, TcpOptions, const
from ipsiblings.preparation.serialization import TargetSerialization

log = liblog.get_root_logger()


class FilesystemProvider:
    def __init__(self):
        self.base_dir = None
        self.skip_ip_versions = []

    def configure(self, conf: config.AppConfig):
        self.base_dir = conf.base_dir
        self.skip_ip_versions = conf.targetprovider.skip_ip_versions

    def provide(self) -> Dict[str, Target]:
        targets: Dict[Tuple, Target] = {}
        with open(
                TargetSerialization.get_targets_path(self.base_dir), 'r', newline='', encoding='utf-8'
        ) as targets_file:
            reader = csv.reader(targets_file, delimiter=const.PRIMARY_DELIMITER)
            for record in reader:
                key, rest = Target.key_and_rest_from(record)
                target = Target(key)
                if target.ip_version in self.skip_ip_versions:
                    continue
                domains_data, tcp_options_str, *ts_data = rest
                for domain in domains_data.split(const.SECONDARY_DELIMITER):
                    target.add_domain(domain)
                target.tcp_options = TcpOptions.from_str(tcp_options_str)
                for even_idx in range(0, len(ts_data) - 1, 2):  # subtract 1 to skip lonely odd indices at the end
                    remote_ts = int(ts_data[even_idx])
                    local_ts = float(ts_data[even_idx + 1])
                    target.handle_timestamp(remote_ts, local_ts, None)
                targets[key] = target
        return {address: target for ((_, address, _), target) in targets.items()}
