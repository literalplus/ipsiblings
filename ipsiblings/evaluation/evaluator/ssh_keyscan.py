import pathlib
from typing import List, Dict, Tuple, Optional

from ipsiblings import logsetup
from ipsiblings.config import AppConfig
from ipsiblings.evaluation.evaluator.evaluator import SiblingEvaluator
from ipsiblings.evaluation.keyscan.export import SshResultImporter, SshResultExporter
from ipsiblings.evaluation.keyscan.property import KeyscanResult, SshProperty
from ipsiblings.evaluation.keyscan.runner import KeyscanRunner
from ipsiblings.evaluation.model.sibling import EvaluatedSibling
from ipsiblings.evaluation.model.status import SiblingStatus
from ipsiblings.model import const

log = logsetup.get_root_logger()


class SshKeyscanEvaluator(SiblingEvaluator):
    """
    Evaluates based on the results of the ssh-keyscan utility, namely host keys and agent string.
    Please note that for proper operation, init_data_for should be called before evaluation.
    """

    @classmethod
    def provide(cls, all_siblings: List[EvaluatedSibling], batch_dir: pathlib.Path, conf: AppConfig):
        # Do not use base_dir from param since we want to share keyscan results between batches
        instance = cls(pathlib.Path(conf.base_dir), conf.eval.ssh_timeout)
        instance.init_data_for(all_siblings)
        return instance

    def __init__(self, base_dir: pathlib.Path, timeout: int):
        super().__init__(const.EvaluatorChoice.SSH_KEYSCAN)
        self._cwd = base_dir
        data_file = self._cwd / 'ssh.tsv'
        self.exporter = SshResultExporter(data_file)
        self.importer = SshResultImporter(data_file)
        self.runner = KeyscanRunner(self._cwd, timeout)
        self.__init_done = False

    def init_data_for(self, all_siblings: List[EvaluatedSibling]):
        relevant_ips = {(ser.ip_version, ser.target_ip) for sibling_series in all_siblings for ser in sibling_series}
        results = self.importer.read_relevant(relevant_ips)
        log.debug(f'Read {len(results)} relevant keyscan results from filesystem.')
        missing_ips = relevant_ips  # read_relevant removes found ips
        if missing_ips:
            log.debug(f'SSH keyscan missing for {len(missing_ips)} addresses, executing.')
            version_result_dict = self.runner.scan(missing_ips)
            new_results: Dict[Tuple[int, str], KeyscanResult] = {}
            for ip_version, result_dict in version_result_dict.items():
                for ip_address, result in result_dict.items():
                    new_results[ip_version, ip_address] = result
            self.exporter.export_append(new_results.values())
            log.debug('SSH keyscan results saved.')
            results.update(new_results)
        else:
            log.debug('All siblings already have SSH keyscan info, skipping.')
        self._apply_results_to(results, all_siblings)
        self.__init_done = True

    def _apply_results_to(
            self, results: Dict[Tuple[int, str], Optional[KeyscanResult]], targets: List[EvaluatedSibling]
    ):
        for scan_target in targets:
            prop = scan_target.contribute_property_type(SshProperty)
            for series in scan_target:
                result = results.get((series.ip_version, series.target_ip))
                if not result:
                    continue
                prop[series.ip_version] = result

    def evaluate(self, evaluated_sibling: EvaluatedSibling) -> SiblingStatus:
        if not self.__init_done:
            raise AssertionError('You probably meant to call init_data_for() first')
        if not evaluated_sibling.has_property(SshProperty):
            return SiblingStatus.ERROR
        prop = evaluated_sibling.get_property(SshProperty)
        if not prop.has_data_for_both():
            # Tempting to return NEGATIVE here, but might be different firewall setups
            return SiblingStatus.INDECISIVE
        if prop.do_agents_match() and prop.do_keys_match():
            return SiblingStatus.POSITIVE
        else:
            return SiblingStatus.NEGATIVE
