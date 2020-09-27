import pathlib
import subprocess
import threading
from collections import defaultdict
from typing import Dict, Optional, Set, Tuple

from ipsiblings import liblog
from ipsiblings.evaluation.keyscan.property import KeyscanResult
from ipsiblings.model import const

log = liblog.get_root_logger()


class SshKeyscanProcessHandler:
    def __init__(self, cwd: pathlib.Path, ip_version: int):
        self._cwd = cwd
        self.ip_version = ip_version
        self.results: Dict[str, KeyscanResult] = {}
        self.thread: Optional[threading.Thread] = None

    def start(self, in_addrs: Set[str]):
        self.thread = threading.Thread(
            target=self._run, args=(in_addrs,), name=f'keyscan-{self.ip_version}'
        )
        self.thread.start()
        log.debug(f'Started SSH keyscan {self.ip_version}.')

    def join(self):
        if not self.thread:
            return
        self.thread.join()
        log.info(f'Finished SSH keyscan {self.ip_version}.')
        self.thread = None

    def _run(self, in_addrs: Set[str]):
        stdin = '\n'.join(in_addrs)
        proc = subprocess.Popen(
            ['ssh-keyscan', '-f', '-', '-T', '3'],  # T: timeout in seconds
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, encoding='utf-8', cwd=self._cwd
        )
        stdout, stderr = proc.communicate(input=stdin, timeout=6)  # seconds
        self._handle_agent_info_in_stderr(stderr)
        self._handle_key_info_in_stdout(stdout)

    def _handle_agent_info_in_stderr(self, stderr: str):
        for line in stderr.strip().split('\n'):
            # stderr contains comments of form # ip:port;agent_string
            if not line.startswith('#'):
                continue
            line_parts = line.strip('#').strip().split(' ', maxsplit=1)
            if len(line_parts) != 2:
                continue
            ip_and_port, agent = line_parts
            ip = ip_and_port[:-len(':22')]
            self.results[ip] = KeyscanResult(self.ip_version, ip, agent)

    def _handle_key_info_in_stdout(self, stdout: str):
        for line in stdout.strip().split('\n'):
            # stdout contains whitespace-separated data: ip key_kind fingerprint_base64
            line_parts = line.strip().split(maxsplit=2)
            if len(line_parts) != 3:
                continue
            ip, kind, fingerprint = line_parts
            if ip in self.results:
                result = self.results[ip]
            else:
                result = KeyscanResult(self.ip_version, ip, const.NONE_MARKER)
            result.register_key(kind, fingerprint)


class KeyscanRunner:
    def __init__(self, cwd: pathlib.Path):
        self._cwd = cwd

    def scan(self, version_ips: Set[Tuple[int, str]]) -> Dict[int, Dict[str, KeyscanResult]]:
        target_dict = defaultdict(set)
        for ipv, ipa in version_ips:
            target_dict[ipv].add(ipa)
        return self._do_scan_for(target_dict)

    def _do_scan_for(self, version_target_ips: Dict[int, Set[str]]) -> Dict[int, Dict[str, KeyscanResult]]:
        version_process_handlers: Dict[int, SshKeyscanProcessHandler] = {
            ipv: SshKeyscanProcessHandler(self._cwd, ipv) for ipv, _ in version_target_ips.items()
        }
        for ip_version, handler in version_process_handlers.items():
            handler.start(version_target_ips[ip_version])
        # Only start waiting for results after all processes are started
        results: Dict[int, Dict[str, KeyscanResult]] = {}
        for ip_version, handler in version_process_handlers.items():
            handler.join()
            results[ip_version] = handler.results
        return results
