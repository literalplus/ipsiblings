from typing import Dict

from ._util import _reduce_map
from .provider import TargetProvider
from ..config import AppConfig
from ..model import DataException, PreparedTargets, Target


def _prepare_pairs(conf: AppConfig, target_provider: TargetProvider) -> Dict[str, Target]:
    targets = target_provider.provide()
    if not targets:
        if conf.targetprovider.resolved_ips_path:
            raise DataException(
                f'Target provider did not provide any candidate pairs '
                f'from {conf.targetprovider.resolved_ips_path}'
            )
        else:
            raise DataException('Target provider did not provide any candidate pairs')
    return _reduce_map(targets, conf, 'candidate pairs')


def run(conf: AppConfig, target_provider: TargetProvider) -> PreparedTargets:
    targets = PreparedTargets(_prepare_pairs(conf, target_provider), type(target_provider).__name__)
    targets.print_summary()
    return targets
