import csv
import pathlib
from collections import defaultdict
from typing import Set, Tuple, Dict, List

from ipsiblings.harvesting.btc.model import BitcoinConnection, BitcoinVersionInfo
from ipsiblings.model import const


class BtcExporter:
    def __init__(self, outdir: pathlib.Path):
        self.outfile = outdir / 'bitcoin.tsv'

    def export_record(self, record):
        ((ipv, ip, port), (first_seen, last_seen), verinfo, addr_data) = record
        with open(self.outfile, 'a', encoding='utf-8', newline='') as fil:
            writer = csv.writer(fil, dialect=csv.excel_tab)
            ver_str = const.SECONDARY_DELIMITER.join([str(x) for x in verinfo]) \
                if verinfo is not None else const.NONE_MARKER
            addr_strs = [const.TERTIARY_DELIMITER.join([str(x) for x in data]) for data in addr_data]
            addr_str = const.SECONDARY_DELIMITER.join(addr_strs)
            writer.writerow((
                ipv, ip, port, first_seen, last_seen, ver_str, addr_str,
            ))


class BtcImporter:
    def __init__(self, indir: pathlib.Path):
        self.infile = indir / 'bitcoin.tsv'

    def read_relevant(self, version_ips: Set[Tuple[int, str]]) -> Dict[Tuple[int, str], List[BitcoinConnection]]:
        results: Dict[Tuple[int, str], List[BitcoinConnection]] = defaultdict(list)
        with open(self.infile, 'r', encoding='utf-8', newline='') as fil:
            reader = csv.reader(fil, dialect=csv.excel_tab)
            for row in reader:
                if len(row) != 7:
                    continue
                (ipvs, ip, ports, *rest) = row
                ipv, port = int(ipvs), int(ports)
                if (ipv, ip) not in version_ips:
                    continue
                (first_seens, last_seens, ver_str, addr_str) = rest
                first_seen, last_seen = int(first_seens), int(last_seens)
                conn = BitcoinConnection(ipv, ip, port, first_seen, last_seen)
                if ver_str != const.NONE_MARKER:
                    (proto_vers, sub_ver, svcs, times, heights) = const.SECONDARY_DELIMITER.split(ver_str)
                    proto_ver, svc, time, height = int(proto_vers), int(svcs), int(times), int(heights)
                    conn.add_verinfo(BitcoinVersionInfo(proto_ver, sub_ver, svc, time, height))
                if addr_str:
                    for addr in const.SECONDARY_DELIMITER.split(addr_str):
                        (atimes, asvcs, aip, aports) = const.TERTIARY_DELIMITER.split(addr)
                        atime, asvc, aport = int(atimes), int(asvcs), int(aports)
                        conn.add_addrinfo(atime, asvc, aip, aport)
                results[(ipv, ip)].append(conn)
        return results
