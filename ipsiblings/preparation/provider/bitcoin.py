import ipaddress
from typing import Dict, Union

import requests

from ipsiblings import config, logsetup
from ipsiblings.model import Target
from .targetprovider import TargetProvider

API_BASE = "https://bitnodes.io/api/v1"
API_SNAPSHOTS = f"{API_BASE}/snapshots"
log = logsetup.get_root_logger()


class BitcoinNodesProvider(TargetProvider):
    def __init__(self):
        self.ip_versions = {4, 6}

    def configure(self, conf: config.AppConfig) -> None:
        self.ip_versions -= conf.targetprovider.skip_ip_versions

    def provide(self) -> Dict[str, Target]:
        """Provide targets as a mapping (ip4, ip6) -> CandidatePair"""
        nodes = self.fetch_nodes()
        targets: Dict[str, Target] = {}
        for node in nodes:
            target = Target(Target.make_key(node.ip_version, node.ip_str, node.port))
            if node.hostname is not None:
                target.add_domain(node.hostname)
            targets[node.ip_str] = target
        return targets

    def fetch_nodes(self):
        raw_nodes = self._obtain_nodes_raw()
        nodes_all_versions = [Node(addr, node_raw) for (addr, node_raw) in raw_nodes.items()]
        # Note that Onion is IP version -1, i.e. excluded here
        return filter(lambda n: n.ip_version in self.ip_versions, nodes_all_versions)

    def _obtain_nodes_raw(self):
        log.debug("Looking for snapshots of Bitcoin network.")
        snapshots = requests.get(API_SNAPSHOTS).json()
        snapshot = snapshots["results"][0]
        log.debug(f" Found {snapshot['url']} with {snapshot['total_nodes']} nodes.")
        snap_data = requests.get(snapshot["url"]).json()
        nodes = snap_data["nodes"]
        log.info(f" Received {len(nodes)} Bitcoin nodes")
        return nodes

    def get_ground_truth_pairs(self):
        by_host = dict()
        for node in self.fetch_nodes():
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

        log.info(f" *** Found {len(candidates)} Bitcoin node duplicates by hostname.")
        return candidates


class Node:
    def __init__(self, addr, raw):
        (self.ip_str, _, self.port) = addr.rpartition(':')
        self.port = int(self.port)
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
