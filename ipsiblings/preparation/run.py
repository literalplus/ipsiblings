from typing import Dict

from ipsiblings.preparation.preparedtargets import PreparedTargets, Target
from ._util import _prepare_trace_set_dirs, _reduce_map
from ..bootstrap import Wiring
from ..bootstrap.exception import DataException


def _prepare_pairs(wiring: Wiring) -> Dict[str, Target]:
    conf = wiring.conf
    targets = wiring.target_provider.provide()
    if not targets:
        if conf.targetprovider.resolved_ips_path:
            raise DataException(
                f'Target provider did not provide any candidate pairs '
                f'from {conf.targetprovider.resolved_ips_path}'
            )
        else:
            raise DataException('Target provider did not provide any candidate pairs')
    return _reduce_map(targets, conf, 'candidate pairs')


def run(wiring: Wiring) -> PreparedTargets:
    conf = wiring.conf
    if not conf.flags.load_tracesets:
        _prepare_trace_set_dirs(conf)
    targets = PreparedTargets(_prepare_pairs(wiring), type(wiring.target_provider).__name__)
    targets.print_summary()
    return targets
