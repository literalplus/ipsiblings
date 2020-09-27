import csv
import pathlib
import subprocess
import threading
from collections import ChainMap
from copy import deepcopy
from typing import Dict, Any, Optional, List, Iterable, Mapping, Tuple, Set

from ipsiblings import liblog
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluatedsibling import EvaluatedSibling, SiblingStatus, FamilySpecificSiblingProperty
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.model import const

log = liblog.get_root_logger()


class SshResult:
    def __init__(self, agent: str):
        self.agent = agent
        self.key_kind_to_fingerprint: Dict[str, str] = {}

    @property
    def key_kinds(self) -> Iterable[str]:
        return self.key_kind_to_fingerprint.keys()

    @classmethod
    def from_raw_export(cls, source: Dict[str, str]) -> Optional['SshResult']:
        if not source.get('agent'):
            return None
        result = SshResult(source['agent'])
        for key, value in source.items():
            prefix = 'key_'
            if key.startswith(prefix):
                result.register_key(key[len(prefix):], value)
        return result

    def register_key(self, kind: str, fingerprint: str):
        self.key_kind_to_fingerprint[kind] = fingerprint

    def export_raw(self) -> Dict[str, str]:
        result = {
            'agent': self.agent,
        }
        result.update({f'key_{kind}': fingerprint for kind, fingerprint in self.key_kind_to_fingerprint.items()})
        return result

    def __deepcopy__(self, memo_dict) -> 'SshResult':
        # NOTE: this is not optimal, but it is ensured to stay consistent with import/export
        # plus definitely does not leak any references :)
        return type(self).from_raw_export(self.export_raw())


class SshProperty(FamilySpecificSiblingProperty[Optional[SshResult]]):
    @classmethod
    def provide_for(cls, evaluated_sibling: EvaluatedSibling) -> 'SshProperty':
        return cls()

    def __init__(self):
        self.data4 = None
        self.data6 = None

    def __setitem__(self, key, value: SshResult):
        if key == 4:
            self.data4 = value
        elif key == 6:
            self.data6 = value
        else:
            raise KeyError

    def has_data_for_both(self):
        return bool(self[4] and self[6])

    def do_agents_match(self) -> Optional[bool]:
        if not self.has_data_for_both():
            return None
        else:
            return self[4].agent == self[6].agent

    def do_keys_match(self) -> Optional[bool]:
        if not self.has_data_for_both():
            return None
        shared_key_kinds = set(self[4].key_kinds).intersection(self[6].key_kinds)
        if not shared_key_kinds:
            return None
        for kind in shared_key_kinds:
            if self[4].key_kind_to_fingerprint[kind] != self[6].key_kind_to_fingerprint[kind]:
                return False
        return True

    def export(self) -> Dict[str, Any]:
        return {
            'both_present': self.has_data_for_both(),
            'agents_match': self.do_agents_match(),
            'keys_match': self.do_keys_match()
        }

    def export_raw(self) -> Mapping[str, str]:
        list_of_result_export_dicts = [{f'{ipv}_{k}': v for k, v in res.export_raw().items()} for ipv, res in self]
        return ChainMap(*list_of_result_export_dicts)

    def import_from_raw(self, source: Mapping[str, str]):
        for ip_version in (4, 6):
            prefix = f'{ip_version}_'
            relevant = {k[len(prefix):]: v for k, v in source.items() if k.startswith(prefix)}
            self[ip_version] = SshResult.from_raw_export(relevant)


class SshResultExporter:
    def __init__(self, out_file: pathlib.Path):
        self.out_file = out_file

    def export(self, evaluated_siblings: List[EvaluatedSibling]):
        exports = [
            ChainMap({'ip4': s[4].target_ip, 'ip6': s[6].target_ip}, s.get_property(SshProperty).export_raw())
            for s in evaluated_siblings
            if s.has_property(SshProperty)
        ]
        all_keys = {k for sublist in exports for k in sublist}
        with open(self.out_file, 'w', encoding='utf-8', newline='') as fil:
            sorted_keys = list(all_keys)
            sorted_keys.sort()
            writer = csv.DictWriter(fil, fieldnames=sorted_keys, dialect=csv.excel_tab)
            writer.writeheader()
            writer.writerows(exports)


class SshResultImporter:
    def __init__(self, in_file: pathlib.Path):
        self.in_file = in_file

    def import_to_report_missing(self, evaluated_siblings: List[EvaluatedSibling]) -> bool:
        if not self.in_file.is_file():
            return bool(evaluated_siblings)  # if there are any, they are missing
        key_to_imported_row = self._import_to_dict()
        any_missing = False
        for evaluated_sibling in evaluated_siblings:
            key = evaluated_sibling[4].target_ip, evaluated_sibling[6].target_ip
            imported_row = key_to_imported_row.get(key)
            if not imported_row:
                any_missing = True
                continue
            prop = evaluated_sibling.contribute_property_type(SshProperty)
            prop.import_from_raw(imported_row)
        return any_missing

    def _import_to_dict(self) -> Dict[Tuple, Mapping[str, str]]:
        imported: Dict[Tuple, Mapping[str, str]] = {}
        with open(self.in_file, 'r', encoding='utf-8', newline='') as fil:
            reader = csv.DictReader(fil, dialect=csv.excel_tab)
            for row in reader:
                try:
                    key = row['ip4'], row['ip6']
                    imported[key] = row
                except KeyError:
                    pass
        return imported


class SshKeyscanProcessHandler:
    def __init__(self, cwd: pathlib.Path):
        self._cwd = cwd
        self.results: Dict[str, SshResult] = {}
        self.thread: Optional[threading.Thread] = None

    def start(self, name: str, in_addrs: Set[str]):
        self.thread = threading.Thread(
            target=self._run, args=(in_addrs,), name=f'keyscan-{name}'
        )
        self.thread.start()
        log.debug(f'Started SSH keyscan {name}.')

    def join(self):
        if not self.thread:
            return
        self.thread.join()
        log.info(f'Finished SSH keyscan {self.thread.name}.')
        self.thread = None

    def _run(self, in_addrs: Set[str]):
        stdin = '\n'.join(in_addrs)
        log.debug(f'stdin -> {in_addrs}')
        proc = subprocess.Popen(
            ['ssh-keyscan', '-f', '-'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, encoding='utf-8', cwd=self._cwd
        )
        stdout, stderr = proc.communicate(input=stdin, timeout=None)
        self._handle_agent_info_in_stderr(stderr)
        self._handle_key_info_in_stdout(stdout)

    def _handle_agent_info_in_stderr(self, stderr: str):
        log.debug(f'stderr -> {stderr}')
        for line in stderr.strip().split('\n'):
            # stderr contains comments of form # ip:port;agent_string
            if not line.startswith('#'):
                continue
            line_parts = line.strip('#').strip().split(' ', maxsplit=1)
            if len(line_parts) != 2:
                continue
            ip_and_port, agent = line_parts
            ip = ip_and_port[:-len(':22')]
            self.results[ip] = SshResult(agent)

    def _handle_key_info_in_stdout(self, stdout: str):
        log.debug(f'stdout -> {stdout}')
        for line in stdout.strip().split('\n'):
            # stdout contains whitespace-separated data: ip key_kind fingerprint_base64
            line_parts = line.strip().split(maxsplit=2)
            if len(line_parts) != 3:
                continue
            ip, kind, fingerprint = line_parts
            if ip in self.results:
                result = self.results[ip]
            else:
                result = SshResult(const.NONE_MARKER)
            result.register_key(kind, fingerprint)


class SshKeyscanEvaluator(SiblingEvaluator):
    """
    Evaluates based on the results of the ssh-keyscan utility, namely host keys and agent string.
    Please note that for proper operation, init_data_for should be called before evaluation.
    """

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], conf: AppConfig):
        instance = cls(pathlib.Path(conf.base_dir))
        instance.init_data_for(all_siblings)
        return instance

    def __init__(self, base_dir: pathlib.Path):
        super().__init__(f'SSH Host Key')
        self._cwd = base_dir
        data_file = self._cwd / 'ssh.tsv'
        self.importer = SshResultImporter(data_file)
        self.exporter = SshResultExporter(data_file)
        self.__init_done = False

    def init_data_for(self, all_siblings: List[EvaluatedSibling]):
        any_missing = self.importer.import_to_report_missing(all_siblings)
        if any_missing:
            log.debug('SSH keyscan needed, executing.')
            results, to_scan = self._do_scan_where_missing(all_siblings)
            self._apply_results_to(results, to_scan)
            self.exporter.export(all_siblings)
            log.debug('SSH keyscan results saved.')
        else:
            log.debug('All siblings already have SSH keyscan info, skipping.')
        self.__init_done = True

    def _do_scan_where_missing(self, all_siblings: List[EvaluatedSibling]):
        to_scan = [
            it for it in all_siblings
            if not it.has_property(SshProperty) or not it.get_property(SshProperty).has_data_for_both()
        ]
        scan_ips: Dict[int, Set[str]] = {4: set(), 6: set()}
        for scan_target in to_scan:
            for ip_version, series in scan_target:
                scan_ips[ip_version].add(series.target_ip)
        results = self._do_scan_for(scan_ips)
        return results, to_scan

    def _do_scan_for(self, version_target_ips: Dict[int, Set[str]]) -> Dict[int, Dict[str, SshResult]]:
        version_process_handlers: Dict[int, SshKeyscanProcessHandler] = {
            ipv: SshKeyscanProcessHandler(self._cwd) for ipv, _ in version_target_ips.items()
        }
        for ip_version, handler in version_process_handlers.items():
            handler.start(str(ip_version), version_target_ips[ip_version])
        # Only start waiting for results after all processes are started
        results: Dict[int, Dict[str, SshResult]] = {}
        for ip_version, handler in version_process_handlers.items():
            handler.join()
            results[ip_version] = handler.results
        return results

    def _apply_results_to(self, results: Dict[int, Dict[str, SshResult]], to_scan: List[EvaluatedSibling]):
        for scan_target in to_scan:
            prop = scan_target.contribute_property_type(SshProperty)
            for ip_version, series in scan_target:
                ipv_results = results.get(ip_version)
                if not ipv_results:
                    continue
                result = ipv_results.get(series.target_ip)
                if not result:
                    continue
                prop[ip_version] = deepcopy(result)

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        if not self.__init_done:
            raise AssertionError('You probably meant to call init_data_for() first')
        if not evaluated_sibling.has_property(SshProperty):
            return SiblingStatus.INDECISIVE
        prop = evaluated_sibling.get_property(SshProperty)
        if not prop.has_data_for_both():
            # Tempting to return NEGATIVE here, but might be different firewall setups
            return SiblingStatus.INDECISIVE
        if prop.do_agents_match() and prop.do_keys_match():
            return SiblingStatus.POSITIVE
        else:
            return SiblingStatus.NEGATIVE
