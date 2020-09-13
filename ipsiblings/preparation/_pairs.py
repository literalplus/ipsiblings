from ipsiblings.preparation.preparedtargets import PreparedPairs
from ipsiblings.preparation.serialization import load_candidate_pairs
from ._util import _reduce_map
from .. import liblog
from ..bootstrap import Wiring
from ..bootstrap.exception import DataException

log = liblog.get_root_logger()


def prepare_pairs(wiring: Wiring) -> PreparedPairs:
    conf = wiring.conf
    if conf.targetprovider.has_resolved:
        ts_data_available = False
        candidate_pairs = wiring.target_provider.provide_candidates()
        if not candidate_pairs:
            if conf.targetprovider.resolved_ips_path:
                raise DataException(
                    f'Target provider did not provide any candidate pairs '
                    f'from {conf.targetprovider.resolved_ips_path}'
                )
            else:
                raise DataException('Target provider did not provide any candidate pairs')
    else:
        log.info(f'Loading candidate file {conf.paths.candidates_csv}')
        # load candidate pairs
        ports_available, ts_data_available, tcp_opts_available, candidate_pairs = load_candidate_pairs(
            conf.paths.candidates_csv, skip_list=wiring.skip_list, include_domain=True
        )
        if not candidate_pairs:
            raise DataException(f'Candidate CSV at {conf.paths.candidates_csv} is empty')
    candidate_pairs = _reduce_map(candidate_pairs, conf, 'candidate pairs')
    nr_candidates_written = 0
    return PreparedPairs(candidate_pairs, True, nr_candidates_written, ts_data_available)
