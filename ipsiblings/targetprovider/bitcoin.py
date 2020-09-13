import ipaddress
from typing import Dict, Union

import requests

from ipsiblings.preparation.candidatepair import CandidatePair
from . import TargetProvider
from .. import config, liblog

API_BASE = "https://bitnodes.io/api/v1"
API_SNAPSHOTS = f"{API_BASE}/snapshots"
log = liblog.get_root_logger()


class BitcoinNodesProvider(TargetProvider):
    def configure(self, conf: config.AppConfig) -> None:
        # No configuration necessary
        pass

    def provide_candidates(self) -> Dict[(str, str), CandidatePair]:
        """Provide targets as a mapping (ip4, ip6) -> CandidatePair"""
        nodes = self.get_nodes()
        nodes4 = [node for node in nodes if node.protocol_version == 4]
        nodes6 = [node for node in nodes if node.protocol_version == 6]
        pairs: Dict[(str, str), CandidatePair] = {}
        for node4 in nodes4:
            for node6 in nodes6:
                pairs[(node4.ip_str, node6.ip_str)] = CandidatePair(
                    node4.ip_str, node6.ip_str,
                    ports4={8333}, ports6={8333},
                    domains={node4.hostname, node6.hostname}
                )
        return pairs

    def _obtain_nodes_raw(self):
        print(" ... Looking for snapshots")
        snapshots = requests.get(API_SNAPSHOTS).json()
        snapshot = snapshots["results"][0]
        print(f" Found {snapshot['url']} with {snapshot['total_nodes']} nodes.")
        snap_data = requests.get(snapshot["url"]).json()
        nodes = snap_data["nodes"]
        print(f" Received {len(nodes)} nodes")
        return nodes

    def get_ground_truth_pairs(self):
        by_host = dict()
        for node in self.get_nodes():
            key = node.hostname
            host_candidates = by_host.get(key, [])
            by_host[key] = host_candidates + [node]

        candidates = [
            (host, raw_nodes) for (host, raw_nodes) in by_host.items()
            if is_ds_node_set(raw_nodes)
        ]

        for (key, raw_nodes) in candidates:
            ips = ", ".join(map(lambda n: n.ip_str, raw_nodes))
            print(f" ->  {key} ~ {ips}")

        print(f" *** Found {len(candidates)} duplicates.")
        return candidates

    def get_nodes(self):
        raw_nodes = self._obtain_nodes_raw()
        nodes_incl_onions = [Node(addr, node_raw) for (addr, node_raw) in raw_nodes.items()]
        return filter(lambda n: not n.is_onion, nodes_incl_onions)


class Node:
    def __init__(self, addr, raw):
        (self.ip_str, _, self.port) = addr.rpartition(':')
        self.ip_str: str = self.ip_str.replace("[", "").replace("]", "")
        self.is_onion: bool = self.ip_str.endswith(".onion")
        self.ip_model: Union[ipaddress.IPv4Address, ipaddress.IPv6Address, None] = \
            ipaddress.ip_address(self.ip_str) if not self.is_onion else None
        self.ip_version: int = self.ip_model.version if self.ip_model else -1
        self.raw = raw
        self.protocol_version = raw[0]  # Bitcoin, not IP
        self.user_agent = raw[1]
        self.hostname: str = raw[5]
        self.location = (raw[7], raw[6])  # country, city
        self.timezone = raw[10]
        self.asn = raw[11]
        self.asn_name = raw[12]

    def __str__(self):
        return f"Node({self.ip_str} at {self.hostname}, from {self.raw})"

    def __repr__(self):
        return str(self)


def is_ds_node_set(nodes):
    if len(nodes) <= 1:
        return False
    non_onions = [n for n in nodes if not n.is_onion]
    ips = [ipaddress.ip_address(n.ip_str) for n in non_onions]
    versions = set([addr.version for addr in ips])
    return len(versions) > 1
