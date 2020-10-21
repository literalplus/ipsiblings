#!/usr/bin/env python3
import math
from collections import defaultdict

from ipsiblings.harvesting.btc.export import BtcImporter
from ipsiblings.harvesting.btc.model import AI_IP

ips_with_addrs = defaultdict(lambda: (0, 0, 0))
pv_ua_ips = defaultdict(set)
seen_addrs = defaultdict(set)


def count_addrs():
    global ips_with_addrs
    importer = BtcImporter('.')
    ip_filter = None
    for conn in importer.yield_relevant(ip_filter):
        conn_key = (conn.ip_ver, conn.ip)
        pv_ua_ips[(conn.ver_info.proto_ver, conn.ver_info.sub_ver)].add(conn_key)
        if conn.addr_infos:
            active_addr_cnt, already_seen = _process_addrs(conn)
            (gcnt, gonl, gseen) = ips_with_addrs[conn_key]
            ncnt = gcnt + 1
            onl_avg = math.ceil((gonl * gcnt + active_addr_cnt) / ncnt)
            seen_avg = math.ceil((gseen * gcnt + already_seen) / ncnt)
            ips_with_addrs[conn_key] = (ncnt, onl_avg, seen_avg)


def _process_addrs(conn):
    global seen_addrs
    active_addr_cnt = 0
    already_seen = 0
    for addr_info in conn.addr_infos:
        aip = addr_info[AI_IP]
        if conn.was_active(addr_info):
            active_addr_cnt += 1
        if aip in seen_addrs:
            seen_by = seen_addrs[aip]
            if len(seen_by) > 1 or aip not in seen_by:
                already_seen += 1
        seen_addrs[aip].add(conn.ip)
    return active_addr_cnt, already_seen


def run():
    count_addrs()
    v_map = defaultdict(lambda: 0)
    print("DATA")
    print("ipvs ip addr_msg_cnt avg_online_addrs avg_already_seen_addrs")
    for ((ipvs, ip), (cnt, onl, seen)) in ips_with_addrs.items():
        print(f'{ipvs}\t{ip}\t{cnt}\t{onl}\t{seen}')
        v_map[ipvs] += 1
    print("BY IP VERSION")
    print("ipvs peers_with_addr_msgs")
    for (ipvs, cnt) in v_map.items():
        print(f'{ipvs}\t{cnt}')
    print("BY BITCOIN VERSION")
    print("proto_ver user_agent peer_cnt")
    for ((proto_ver, user_agent), ips) in pv_ua_ips.items():
        print(f'{proto_ver}\t{user_agent}\t{len(ips)}')


if __name__ == '__main__':
    run()
