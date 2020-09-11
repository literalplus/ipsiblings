from ipsiblings.preparation.preparedtargets import PreparedPairs
from ._util import _reduce_map
from .. import liblog, libconstants
from ..bootstrap import Wiring
from ..bootstrap.exception import DataException
from ..libts.portscan import CandidatePortScan
from ..libts.serialization import load_candidate_pairs, write_candidate_pairs

log = liblog.get_root_logger()


def prepare_pairs(wiring: Wiring) -> PreparedPairs:
    conf = wiring.conf
    if conf.targetprovider.has_resolved:
        ports_available = False
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
    ip_cp_lut = {}  # { ip: [ CandidatePair ] }
    if not ports_available or not ts_data_available:
        for ip_tuple, cp in candidate_pairs.items():
            ip4, ip6 = ip_tuple
            if ip4 in ip_cp_lut:
                ip_cp_lut[ip4].append(cp)
            else:
                ip_cp_lut[ip4] = [cp]
            if ip6 in ip_cp_lut:
                ip_cp_lut[ip6].append(cp)
            else:
                ip_cp_lut[ip6] = [cp]
    nr_candidates_written = 0
    if not ports_available:
        try:
            # no ports in csv file available -> find open ports with TSNode
            if not conf.targetprovider.has_resolved:
                log.info('No open ports available in candidate file')

            nodes4 = set()  # do not add IPs more than once
            nodes6 = set()
            for cp in candidate_pairs.values():
                nodes4.add(cp.ip4)
                nodes6.add(cp.ip6)

            log.info('Starting port scan on candidate pairs')

            cpscan = CandidatePortScan(
                nodes4, nodes6, wiring.nic, port_list=libconstants.PORT_LIST
            ).start()

            while not cpscan.finished():
                # do not choose this value too high otherwise the function will never return because
                # there always will be data available (queue.empty exception will never be raised)
                # 1.5 seconds seems to be the optimum for debug output
                cpscan.process_results(ip_cp_lut, timeout=1.5)
            cpscan.process_results(ip_cp_lut, timeout=3)
            cpscan.stop()  # must be explicitly stopped!

            log.info('Port scan on candidate pairs done.')
        finally:
            # write responding candidate pairs to file (no timestamp data!)
            if not ports_available:
                nr_candidates_written, nr_data_records_written = write_candidate_pairs(
                    candidate_pairs,
                    conf.base_dir,
                    only_active_nodes=True,
                    write_candidates=True,
                    write_ts_data=False,
                    write_tcp_opts_data=True,
                    include_domain=True
                )
    return PreparedPairs(candidate_pairs, ports_available, nr_candidates_written, ts_data_available)
