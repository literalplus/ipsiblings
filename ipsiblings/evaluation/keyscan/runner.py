import pathlib
import subprocess
import threading
from collections import defaultdict
from itertools import islice
from typing import Dict, Optional, Set, Tuple, Iterable, List, Iterator

from ipsiblings import logsetup
from ipsiblings.evaluation.keyscan.property import KeyscanResult
from ipsiblings.model import const

log = logsetup.get_root_logger()


class KeyscanProcessHandler:
    """
    Handles ssh-keyscan interaction for a single process.
    """

    def __init__(self, cwd: pathlib.Path, ip_version: int, timeout: int):
        self._cwd = cwd
        self.ip_version = ip_version
        self.timeout = timeout
        self.results: Dict[str, KeyscanResult] = {}
        self.thread: Optional[threading.Thread] = None
        self.failed = False

    def start(self, in_addrs: Set[str]):
        if not in_addrs:
            log.info(f'No input addresses for keyscan {self.ip_version}, skipping.')
            return
        self.thread = threading.Thread(
            target=self._run, args=(in_addrs,), name=f'keyscan-{self.ip_version}'
        )
        self.thread.start()

    def join(self):
        if not self.thread:
            return
        self.thread.join()
        log.info(f'Finished SSH keyscan {self.ip_version}.')
        self.thread = None

    def _run(self, in_addrs: Set[str]):
        log.debug(f'Started SSH keyscan {self.ip_version}, input size {len(in_addrs)}.')
        stdin = '\n'.join(in_addrs)
        proc = subprocess.Popen(
            ['ssh-keyscan', '-f', '-', '-T', '2'],  # T: timeout in seconds
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            universal_newlines=True, encoding='utf-8', cwd=self._cwd
        )
        try:
            natural_timeout = 4 * len(in_addrs) + 5
            if natural_timeout > self.timeout:
                self.timeout = natural_timeout
                log.info(
                    f'Increasing SSH keyscan {self.ip_version} timeout to {natural_timeout} '
                    f'due to large input size of {len(in_addrs)}.'
                )
            stdout, stderr = proc.communicate(input=stdin, timeout=self.timeout)  # seconds
            self._handle_agent_info_in_stderr(stderr)
            self._handle_key_info_in_stdout(stdout)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, stderr = proc.communicate()
            self._handle_agent_info_in_stderr(stderr)
            self._handle_key_info_in_stdout(stdout)
            log.warn(f'SSH keyscan {self.ip_version} timed out.')
            self.failed = True
        log.debug(f'SSH keyscan {self.ip_version} thread exited.')

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
    """
    Runs an entire SSH key scan with multiple processes.
    """

    def __init__(self, cwd: pathlib.Path, timeout: int):
        self._cwd = cwd
        self.timeout = timeout

    def scan(self, version_ips: Set[Tuple[int, str]]) -> Dict[int, Dict[str, KeyscanResult]]:
        target_dict = defaultdict(set)
        for ipv, ipa in version_ips:
            target_dict[ipv].add(ipa)
        return self._do_scan_for(target_dict)

    def _do_scan_for(self, version_target_ips: Dict[int, Set[str]]) -> Dict[int, Dict[str, KeyscanResult]]:
        ipv_handlers: List[Tuple[int, KeyscanProcessHandler]] = []
        for ip_version, target_ips in version_target_ips.items():
            for batch in self._as_batches(target_ips, 200):
                handler = KeyscanProcessHandler(self._cwd, ip_version, self.timeout)
                handler.start(batch)
                ipv_handlers.append((ip_version, handler))
        results: Dict[int, Dict[str, KeyscanResult]] = defaultdict(dict)
        # Only start waiting for results after all processes are started
        for ip_version, handler in ipv_handlers:
            handler.join()
            results[ip_version].update(handler.results)
        for ip_version, target_ips in version_target_ips.items():
            for address in target_ips:
                if address not in results[ip_version]:
                    results[ip_version][address] = KeyscanResult(ip_version, address, const.NONE_MARKER)
        return results

    def _as_batches(self, inp: Iterable[str], batch_size: int) -> Iterator[Set[str]]:
        iterator = iter(inp)
        while True:  # gotta love Debian only shipping Python 3.7, so cannot use Walrus operator :(
            batch = set(islice(iterator, batch_size))
            if not batch:
                return
            yield batch
