import csv
import pathlib
from collections import defaultdict
from typing import Set, Tuple, Dict, List, Optional, Union, Iterable

from typing.io import IO

from ipsiblings.harvesting.btc.model import BitcoinConnection, BitcoinVersionInfo
from ipsiblings.model import const


class BtcExporter:
    def __init__(self, outdir: str):
        self.outfile = pathlib.Path(outdir) / 'bitcoin.tsv'
        self.cache_file = False
        self._cached_fp: Optional[IO] = None

    def export_record(self, record):
        ((ipv, ip, port), (first_seen, last_seen), verinfo, addr_data) = record
        if verinfo is None:
            return  # Nothing to analyse in this case
        ver_str = const.SECONDARY_DELIMITER.join([str(x) for x in verinfo])
        addr_strs = [const.TERTIARY_DELIMITER.join([str(x) for x in data]) for data in addr_data]
        addr_str = const.SECONDARY_DELIMITER.join(addr_strs)
        tup = (ipv, ip, port, first_seen, last_seen, ver_str, addr_str)
        if self.cache_file and not self._cached_fp:
            self._cached_fp = self._create_fp()
        if self._cached_fp:
            self._write_to_fp(self._cached_fp, tup)
        else:
            with self._create_fp() as fil:
                self._write_to_fp(fil, tup)

    def _create_fp(self):
        return open(self.outfile, 'a', encoding='utf-8', newline='')

    def _write_to_fp(self, fil, tup):
        csv.writer(fil, dialect=csv.excel_tab).writerow(tup)

    def close(self):
        if self._cached_fp:
            self._cached_fp.close()


class BtcImporter:
    def __init__(self, indir: Union[str, pathlib.Path]):
        self.infile = pathlib.Path(indir) / 'bitcoin.tsv'

    def read_relevant(self, version_ips: Set[Tuple[int, str]]) -> Dict[Tuple[int, str], List[BitcoinConnection]]:
        results: Dict[Tuple[int, str], List[BitcoinConnection]] = defaultdict(list)
        for conn in self.yield_relevant(version_ips):
            results[(conn.ip_ver, conn.ip)] += conn
        return results

    def yield_relevant(
            self, version_ips: Optional[Set[Tuple[int, str]]]
    ) -> Iterable[BitcoinConnection]:
        with open(self.infile, 'r', encoding='utf-8', newline='') as fil:
            reader = csv.reader(fil, dialect=csv.excel_tab)
            for row in reader:
                if len(row) != 7:
                    continue
                (ipvs, ip, ports, *rest) = row
                ipv, port = int(ipvs), int(ports)
                if version_ips and (ipv, ip) not in version_ips:
                    continue
                yield self._parse_rest(ip, ipv, port, rest)

    def _parse_rest(self, ip, ipv, port, rest: Tuple[str, str, str, str]):
        (first_seens, last_seens, ver_str, addr_str) = rest
        first_seen, last_seen = float(first_seens), float(last_seens)
        ver_info = self._parse_ver_info(ver_str)
        conn = BitcoinConnection(ipv, ip, port, first_seen, last_seen, ver_info)
        if addr_str:
            for addr in addr_str.split(const.SECONDARY_DELIMITER):
                (atimes, asvcs, addr_rest) = addr.split(const.TERTIARY_DELIMITER, maxsplit=2)
                (aip, aports) = addr_rest.rsplit(const.TERTIARY_DELIMITER, maxsplit=1)
                atime, asvc, aport = int(atimes), int(asvcs), int(aports)
                conn.add_addrinfo(atime, asvc, aip, aport)
        return conn

    def _parse_ver_info(self, ver_str):
        (proto_vers, sub_ver, svcs, times, heights) = ver_str.split(const.SECONDARY_DELIMITER)
        proto_ver, svc, time, height = int(proto_vers), int(svcs), int(times), int(heights)
        verinfo = BitcoinVersionInfo(proto_ver, sub_ver, svc, time, height)
        return verinfo
