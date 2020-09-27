import csv
import pathlib
from typing import Dict, Tuple, Optional, Set, Iterable

from ipsiblings import liblog
from ipsiblings.evaluation.keyscan.property import KeyscanResult
from ipsiblings.model import const

log = liblog.get_root_logger()

_KEY_IP_VERSION = 'ipv'
_KEY_IP_ADDRESS = 'ip'
_KEY_AGENT = 'agent'
_KEY_KEYS = 'keys'
_CSV_FIELD_NAMES = [_KEY_IP_VERSION, _KEY_IP_ADDRESS, _KEY_AGENT, _KEY_KEYS]


class SshResultExporter:
    def __init__(self, out_file: pathlib.Path):
        self.out_file = out_file

    def export_append(self, results: Iterable[KeyscanResult]):
        existed_before = self.out_file.is_file()
        with open(self.out_file, 'a', encoding='utf-8', newline='') as fil:
            writer = csv.DictWriter(fil, fieldnames=_CSV_FIELD_NAMES, dialect=csv.excel_tab)
            if not existed_before:
                writer.writeheader()
            for result in results:
                writer.writerow(self._prepare_row(result))

    def _prepare_row(self, result: KeyscanResult) -> Dict[str, str]:
        key_strings = [f'{k}{const.TERTIARY_DELIMITER}{fp}' for k, fp in result.key_kind_to_fingerprint.items()]
        return {
            _KEY_IP_VERSION: result.ip_version,
            _KEY_IP_ADDRESS: result.ip_address,
            _KEY_AGENT: result.agent
            if result.agent else const.NONE_MARKER,
            _KEY_KEYS: const.SECONDARY_DELIMITER.join(key_strings)
            if result.key_kind_to_fingerprint else const.NONE_MARKER,
        }


class SshResultImporter:
    def __init__(self, in_file: pathlib.Path):
        self.in_file = in_file

    def read_relevant(self, version_ips: Set[Tuple[int, str]]) -> Dict[Tuple[int, str], KeyscanResult]:
        """
        Read relevant results as specified by version_ips and removes found entries from the set.
        Return a mapping (ip_version, ip_address) -> result
        """
        if not self.in_file.is_file():
            return {}
        imported: Dict[Tuple[int, str], KeyscanResult] = {}
        with open(self.in_file, 'r', encoding='utf-8', newline='') as fil:
            reader = csv.DictReader(fil, fieldnames=_CSV_FIELD_NAMES, dialect=csv.excel_tab)
            for row in reader:
                ip_version = row.get(_KEY_IP_VERSION)
                ip_address = row.get(_KEY_IP_ADDRESS)
                if ip_version and ip_address and \
                        (ip_version, ip_address) in version_ips:
                    key = int(ip_version), ip_address
                    instance = self._row_to_instance(key, row)
                    if instance:
                        imported[key] = instance
                        version_ips.remove(key)
        return imported

    def _row_to_instance(self, key: Tuple[int, str], source: Dict[str, str]) -> Optional['KeyscanResult']:
        ip_version, ip_address = key
        agent = source.get(_KEY_AGENT)
        if not agent or agent == const.NONE_MARKER:
            return None
        result = KeyscanResult(ip_version, ip_address, agent)
        keys = source.get(_KEY_KEYS)
        if keys and keys != const.NONE_MARKER:
            for key_data in keys.split(const.SECONDARY_DELIMITER):
                kind, fingerprint = key_data.split(const.TERTIARY_DELIMITER)
                result.register_key(kind, fingerprint)
        result.lock()
        return result
