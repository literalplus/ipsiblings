#!/usr/bin/env python3
import requests
from .model import *

API_BASE = "https://bitnodes.io/api/v1"
API_SNAPSHOTS = f"{API_BASE}/snapshots"

print(" ... Looking for snapshots")
snapshots = requests.get(API_SNAPSHOTS).json()
snapshot = snapshots["results"][0]
print(f" Found {snapshot['url']} with {snapshot['total_nodes']} nodes.")

snap_data = requests.get(snapshot["url"]).json()
nodes = snap_data["nodes"]
print(f" Received {len(nodes)} data points")

by_host = dict()

for (addr, node_raw) in nodes.items():
    node = Node(addr, node_raw)
    key = node.hostname
    host_candidates = by_host.get(key, [])
    by_host[key] = host_candidates + [node]

print(f" Reduced to {len(by_host)} hostnames")
lost_onions = [
    ns for ns in by_host.values()
        if len([n for n in ns if n.is_onion]) > 1
]
print(f"  Lost {len(lost_onions)} onion nodes with host siblings")
candidates = [
    (host, nodes) for (host, nodes) in by_host.items() 
        if is_ds_node_set(nodes)
]

for (key, nodes) in candidates:
    ips = ", ".join(map(lambda n: n.ip, nodes))
    print(f" ->  {key} ~ {ips}")

print(f" *** Found {len(candidates)} duplicates.")
