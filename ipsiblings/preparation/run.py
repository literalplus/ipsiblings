from ipsiblings.preparation.preparedtargets import PreparedTargets
from ._pairs import prepare_pairs
from ._util import _prepare_trace_set_dirs
from ..bootstrap import Wiring
from ..bootstrap.exception import ConfigurationException


def _do_prepare(wiring: Wiring) -> PreparedTargets:
    conf = wiring.conf
    if conf.candidates.available:
        return prepare_pairs(wiring)
    else:
        raise ConfigurationException('No valid action requested.')


def run(wiring: Wiring) -> PreparedTargets:
    conf = wiring.conf
    if not conf.flags.load_tracesets:
        _prepare_trace_set_dirs(conf)
    prepared_targets = _do_prepare(wiring)
    prepared_targets.print_summary()
    return prepared_targets
